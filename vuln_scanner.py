import argparse
import socket
import ssl
import sys
import datetime
import http.client
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


OUTDATED_SIGNATURES = [
  
    ("OpenSSH_7.", "OpenSSH 7.x is old; upgrade to 8.x+ for latest security fixes (e.g. CVE-2018-15473 user enumeration)."),
    ("OpenSSH_6.", "OpenSSH 6.x is significantly outdated and has multiple known CVEs."),
    ("Apache/2.2", "Apache 2.2.x reached end-of-life; upgrade to 2.4.x."),
    ("Apache/2.4.6", "Older Apache 2.4 build; check against CVE-2017-7679, CVE-2017-9798 (Optionsbleed)."),
    ("nginx/1.1", "Very old nginx build; multiple known CVEs, upgrade recommended."),
    ("nginx/1.14", "nginx 1.14 predates several security patches; consider upgrading."),
    ("vsftpd 2.3.4", "vsftpd 2.3.4 has a well-known backdoor vulnerability (CVE-2011-2523)."),
    ("ProFTPD 1.3.3", "ProFTPD 1.3.3 has a known backdoor vulnerability."),
    ("Microsoft-IIS/6.0", "IIS 6.0 is unsupported/EOL and has known remote code execution CVEs (e.g. CVE-2017-7269)."),
    ("Microsoft-IIS/7.0", "IIS 7.0 is old; verify patch level."),
]


RISKY_PORTS = {
    21: "FTP often transmits credentials in plaintext; verify it's not allowing anonymous login.",
    23: "Telnet transmits everything (including credentials) unencrypted -- should generally be disabled in favor of SSH.",
    139: "NetBIOS exposed to the network can leak host/user information.",
    445: "SMB exposed externally is a common ransomware/worm vector (e.g. EternalBlue) -- verify patching and firewall rules.",
    3389: "RDP exposed to the internet is a top brute-force / ransomware entry point -- restrict with a VPN or firewall.",
    5900: "VNC is often left with weak or no authentication -- verify a strong password is set.",
    6379: "Redis has historically shipped with no authentication by default -- verify 'requirepass' is set.",
    27017: "MongoDB has historically been left open with no authentication -- verify auth is enabled.",
}


def scan_port(target, port, timeout):
    """Attempt a TCP connect to a single port. Returns True if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target, port))
            return result == 0
    except socket.error:
        return False


def grab_banner(target, port, timeout):
    """Try to read a service banner from an open port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target, port))
            # Some services (HTTP) need a nudge before they respond
            if port in (80, 8080):
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port in (443, 8443):
                return grab_tls_banner(target, port, timeout)
            banner = s.recv(1024).decode(errors="ignore").strip()
            return banner
    except Exception:
        return ""


def grab_tls_banner(target, port, timeout):
    """Grab basic TLS cert info + a HEAD response for HTTPS ports."""
    info = ""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((target, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                cert_info = ssock.getpeercert()
                not_after = ""
                if cert_info and "notAfter" in cert_info:
                    not_after = cert_info["notAfter"]
                    try:
                        expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        if expiry < datetime.datetime.utcnow():
                            not_after += "  [EXPIRED]"
                    except ValueError:
                        pass
                ssock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                http_resp = ssock.recv(1024).decode(errors="ignore")
                server_line = ""
                for line in http_resp.split("\r\n"):
                    if line.lower().startswith("server:"):
                        server_line = line
                info = f"TLS cert expires: {not_after or 'unknown'} | {server_line}"
    except Exception as e:
        info = f"(TLS handshake failed: {e})"
    return info


def check_http_headers(target, port, use_ssl=False):
    """Check for missing common security headers on a web service."""
    findings = []
    try:
        conn = (http.client.HTTPSConnection(target, port, timeout=3)
                if use_ssl else http.client.HTTPConnection(target, port, timeout=3))
        conn.request("GET", "/")
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()

        security_headers = [
            "strict-transport-security",
            "x-content-type-options",
            "x-frame-options",
            "content-security-policy",
        ]
        missing = [h for h in security_headers if h not in headers]
        if missing:
            findings.append(f"Missing security headers: {', '.join(missing)}")
        if "server" in headers:
            findings.append(f"Server header exposes software info: {headers['server']}")
    except Exception:
        pass
    return findings


def check_ftp_anonymous(target, timeout):
    """Passive check: does the FTP banner/login flow allow 'anonymous'?"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target, 21))
            s.recv(1024)  # banner
            s.sendall(b"USER anonymous\r\n")
            resp = s.recv(1024).decode(errors="ignore")
            if resp.startswith("331") or resp.startswith("230"):
                s.sendall(b"PASS anonymous@test.com\r\n")
                resp2 = s.recv(1024).decode(errors="ignore")
                if resp2.startswith("230"):
                    return True
    except Exception:
        pass
    return False


def match_outdated(banner):
    hits = []
    for sig, note in OUTDATED_SIGNATURES:
        if sig.lower() in banner.lower():
            hits.append(note)
    return hits


def parse_port_range(range_str):
    ports = set()
    for chunk in range_str.split(","):
        if "-" in chunk:
            start, end = chunk.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(chunk))
    return sorted(ports)


def run_scan(target, ports, timeout, max_workers=100):
    open_ports = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {executor.submit(scan_port, target, p, timeout): p for p in ports}
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                pass
    return sorted(open_ports)


def build_report(target, results):
    lines = []
    lines.append("=" * 70)
    lines.append(f"VULNERABILITY SCAN REPORT")
    lines.append(f"Target: {target}")
    lines.append(f"Generated: {datetime.datetime.now().isoformat()}")
    lines.append("=" * 70)

    if not results:
        lines.append("\nNo open ports found in the scanned range.")
        return "\n".join(lines), []

    findings_summary = []

    for r in results:
        lines.append(f"\n[+] Port {r['port']} ({r['service_guess']}) - OPEN")
        if r["banner"]:
            lines.append(f"    Banner: {r['banner'][:200]}")
        if r["outdated_hits"]:
            for hit in r["outdated_hits"]:
                lines.append(f"    [!] OUTDATED/VULNERABLE: {hit}")
                findings_summary.append(f"Port {r['port']}: {hit}")
        if r["risky_note"]:
            lines.append(f"    [!] WEAK CONFIG RISK: {r['risky_note']}")
            findings_summary.append(f"Port {r['port']}: {r['risky_note']}")
        if r.get("anonymous_ftp"):
            lines.append(f"    [!] CRITICAL: Anonymous FTP login is ALLOWED.")
            findings_summary.append(f"Port {r['port']}: Anonymous FTP login allowed.")
        for h in r.get("header_findings", []):
            lines.append(f"    [!] {h}")
            findings_summary.append(f"Port {r['port']}: {h}")

    lines.append("\n" + "=" * 70)
    lines.append(f"SUMMARY: {len(results)} open port(s), {len(findings_summary)} finding(s) flagged.")
    lines.append("=" * 70)

    if findings_summary:
        lines.append("\nFlagged issues:")
        for f in findings_summary:
            lines.append(f"  - {f}")
    else:
        lines.append("\nNo outdated versions or obvious weak configs detected among open ports.")
        lines.append("(This does NOT mean the target is secure -- this is a basic educational scan.)")

    return "\n".join(lines), findings_summary


def build_html_report(target, results, findings_summary, text_report):
    rows = ""
    for r in results:
        issues = []
        if r["outdated_hits"]:
            issues.extend(r["outdated_hits"])
        if r["risky_note"]:
            issues.append(r["risky_note"])
        if r.get("anonymous_ftp"):
            issues.append("Anonymous FTP login allowed.")
        issues.extend(r.get("header_findings", []))
        issue_html = "<br>".join(f"⚠ {i}" for i in issues) if issues else "<span style='color:#2e7d32'>No issues flagged</span>"
        rows += f"""
        <tr>
          <td>{r['port']}</td>
          <td>{r['service_guess']}</td>
          <td style="font-family:monospace;font-size:12px">{(r['banner'][:120] or '-')}</td>
          <td>{issue_html}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Vulnerability Scan Report - {target}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#f7f7f9; margin:0; padding:2rem; color:#1a1a1a; }}
  .container {{ max-width: 900px; margin: 0 auto; background:#fff; border-radius:10px; padding:2rem; box-shadow:0 1px 4px rgba(0,0,0,.08); }}
  h1 {{ font-size:1.4rem; margin-bottom:0.2rem; }}
  .meta {{ color:#666; font-size:0.9rem; margin-bottom:1.5rem; }}
  table {{ width:100%; border-collapse: collapse; margin-top:1rem; }}
  th, td {{ text-align:left; padding:10px 12px; border-bottom:1px solid #eee; vertical-align:top; font-size:0.92rem; }}
  th {{ background:#fafafa; text-transform:uppercase; font-size:0.75rem; letter-spacing:.03em; color:#555; }}
  .summary {{ background:#fff8e1; border:1px solid #ffe082; border-radius:8px; padding:1rem 1.2rem; margin-top:1.5rem; }}
  .badge {{ display:inline-block; padding:2px 8px; border-radius:12px; background:#ffe0e0; color:#c62828; font-size:0.8rem; font-weight:600; }}
</style></head>
<body>
  <div class="container">
    <h1>Vulnerability Scan Report</h1>
    <div class="meta">Target: <strong>{target}</strong> &middot; Generated {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}</div>
    <div class="summary">
      <span class="badge">{len(results)} open port(s)</span>
      &nbsp; <span class="badge">{len(findings_summary)} finding(s)</span>
    </div>
    <table>
      <tr><th>Port</th><th>Service</th><th>Banner</th><th>Findings</th></tr>
      {rows if rows else '<tr><td colspan="4">No open ports found.</td></tr>'}
    </table>
    <p style="margin-top:2rem;font-size:0.8rem;color:#999;">
      Educational scan only. Not a substitute for a full professional penetration test.
    </p>
  </div>
</body></html>"""
    return html


def main():
    parser = argparse.ArgumentParser(description="Simple vulnerability scanner (educational).")
    parser.add_argument("target", help="Target hostname or IP (must be authorized for testing)")
    parser.add_argument("--ports", default="1-1024",
                         help="Port range/list, e.g. '1-1024' or '21,22,80,443' (default: 1-1024)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument("--out", default="report", help="Output file prefix (default: report)")
    args = parser.parse_args()

    print(f"[*] Resolving target: {args.target}")
    try:
        socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[!] Could not resolve target '{args.target}'. Exiting.")
        sys.exit(1)

    ports = parse_port_range(args.ports)
    print(f"[*] Scanning {len(ports)} ports on {args.target} (timeout={args.timeout}s)...")

    open_ports = run_scan(args.target, ports, args.timeout)
    print(f"[*] Found {len(open_ports)} open port(s). Grabbing banners...")

    results = []
    for port in open_ports:
        service_guess = COMMON_PORTS.get(port, "Unknown")
        banner = grab_banner(args.target, port, args.timeout)
        outdated_hits = match_outdated(banner)
        risky_note = RISKY_PORTS.get(port, "")
        header_findings = []
        anonymous_ftp = False

        if port in (80, 8080):
            header_findings = check_http_headers(args.target, port, use_ssl=False)
        elif port in (443, 8443):
            header_findings = check_http_headers(args.target, port, use_ssl=True)
        elif port == 21:
            anonymous_ftp = check_ftp_anonymous(args.target, args.timeout)

        results.append({
            "port": port,
            "service_guess": service_guess,
            "banner": banner,
            "outdated_hits": outdated_hits,
            "risky_note": risky_note,
            "header_findings": header_findings,
            "anonymous_ftp": anonymous_ftp,
        })

    text_report, findings_summary = build_report(args.target, results)
    html_report = build_html_report(args.target, results, findings_summary, text_report)

    txt_path = f"{args.out}.txt"
    html_path = f"{args.out}.html"
    json_path = f"{args.out}.json"

    with open(txt_path, "w") as f:
        f.write(text_report)
    with open(html_path, "w") as f:
        f.write(html_report)
    with open(json_path, "w") as f:
        json.dump({"target": args.target, "generated": datetime.datetime.now().isoformat(),
                    "results": results, "findings_summary": findings_summary}, f, indent=2)

    print("\n" + text_report)
    print(f"\n[*] Reports saved: {txt_path}, {html_path}, {json_path}")


if __name__ == "__main__":
    main()
