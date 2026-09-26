# phishing_detector
Scikit-learn phishing email classifier using TF-IDF and engineered URL/keyword features, with accuracy and confusion matrix reporting.
Phishing Email Detection Model

A machine learning model built with Scikit-learn that classifies emails as Phishing or Safe using a combination of TF-IDF text analysis and hand-engineered features (URLs, keywords, formatting patterns).

Features
Text analysis: TF-IDF vectorization (unigrams + bigrams) to capture suspicious wording patterns
Engineered features: URL count, raw IP-based links, shortened URLs (bit.ly, tinyurl, etc.), suspicious TLDs, urgency keywords ("verify", "suspended", "act now"), dollar amounts, exclamation marks, generic greetings ("Dear Customer")
Classifier: Random Forest (default) or Logistic Regression
Evaluation: accuracy, precision/recall/F1, and a confusion matrix plot
Prediction mode: classify a single new email from the command line
Works out of the box: auto-generates a synthetic demo dataset if no real dataset is provided
Installation
bash
pip install scikit-learn pandas numpy matplotlib seaborn joblib
Usage
Train on the built-in synthetic demo dataset
bash
python3 phishing_detector.py

This generates a labeled dataset (synthetic_emails.csv), trains the model, and prints accuracy, a classification report, and a confusion matrix (confusion_matrix.png). The trained model is saved to phishing_model.joblib.

Train on your own dataset
bash
python3 phishing_detector.py --data your_emails.csv

Your CSV needs two columns:

text	label
"URGENT: verify your account..."	phishing
"Hi, here's the agenda for..."	safe

Recommended real-world datasets:

Kaggle "Phishing Email Detection Dataset"
Nazario phishing corpus + Enron ham emails (combined)
Switch model type
bash
python3 phishing_detector.py --model logistic
Classify a new email
bash
python3 phishing_detector.py --predict "URGENT: Your account has been suspended. Verify now at http://secure-login.xyz"

Outputs the predicted label and confidence score using the most recently trained model.

Output
confusion_matrix.png — heatmap of actual vs. predicted labels
phishing_model.joblib — trained model + vectorizer + scaler, reusable for predictions
Console output — accuracy, F1 score, full classification report
Notes
The bundled synthetic dataset is for demonstrating the pipeline end-to-end; it produces unrealistically high accuracy because the templates are cleanly separable. For a meaningful, defensible result, train on a real labeled dataset via --data.
This project is for educational purposes (e.g. coursework in security/ML). It is not a production-grade spam/phishing filter.
