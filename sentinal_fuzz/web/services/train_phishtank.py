"""
Script to train the ML model based on the PhishTank online-valid.csv dataset.
Usage: python train_phishtank.py <path_to_online-valid.csv>
If no CSV is provided, it simulates training with sample data for demonstration.
"""

import sys
from pathlib import Path
import urllib.request
import traceback

try:
    import pandas as pd
    from sklearn.pipeline import Pipeline
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    import joblib
except ImportError:
    print("Installing requirements. Run: pip install scikit-learn pandas joblib")
    sys.exit(1)

from ml_model import MODEL_PATH

def load_phishtank(csv_path: str):
    print(f"Loading dataset from {csv_path}...")
    try:
        df_phish = pd.read_csv(csv_path)
        url_col = "url" if "url" in df_phish.columns else df_phish.columns[0]
        return df_phish[url_col].dropna().tolist()
    except Exception as e:
        print(f"Failed to read CSV: {e}")
        return []

def train_model(csv_path: str = None):
    phish_urls = []
    
    if csv_path and Path(csv_path).exists():
        phish_urls = load_phishtank(csv_path)
    else:
        print("No valid CSV found or provided. Using embedded simulated phishing data to train the model...")
        # Simulate some data based on typical phishing tank data
        phish_urls = [
            "http://login-secure-update.com/paypal/login",
            "https://verify-appleid-account-info.xyz/",
            "http://192.168.1.1/admin/login.php",
            "http://secure-wellsfargo-update.com",
            "https://sbi.bank.in.verify-kyc.com/",
            "http://www.netflix-cancel-subscription.club",
            "https://amazon-prime-reward-claim.info",
            "http://webmail-admin-upgrade.ga",
            "http://support-microsoft-365.online",
        ] * 50 # Duplicate to give model some weight

    if not phish_urls:
        print("No phishing URLs to train on!")
        return

    print(f"Loaded {len(phish_urls)} phishing URLs.")
    
    # Generate benign URLs for training
    # Since Phishtank only has malicious URLs, we need authentic URLs to teach the model the difference.
    print("Generating authentic benign dataset...")
    benign_urls = [
        "https://www.google.com/",
        "https://mail.google.com/mail/u/0/#inbox",
        "https://www.facebook.com/login",
        "https://www.amazon.com/gp/cart/view.html",
        "https://outlook.live.com/mail/0/inbox",
        "https://retail.onlinesbi.sbi/retail/login.htm",
        "https://www.sbi.co.in/web/personal-banking",
        "https://sbi.bank.in/services",
        "https://en.wikipedia.org/wiki/Machine_learning",
        "https://stackoverflow.com/questions/12345/how-to-train-model",
        "https://www.nytimes.com/section/world",
        "https://github.com/Sentinel-Fuzz"
    ] * (len(phish_urls) // 10 + 1)
        
    all_urls = phish_urls + benign_urls
    labels = [1]*len(phish_urls) + [0]*len(benign_urls)
    
    df = pd.DataFrame({"url": all_urls, "label": labels})
    
    print("Building TF-IDF + Logistic Regression ML Pipeline...")
    # Pipeline using Character N-Grams (very effective for URL analysis)
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(analyzer='char', ngram_range=(2, 5), min_df=2)),
        ('clf', LogisticRegression(max_iter=1000, class_weight='balanced', random_state=42))
    ])
    
    print("Training algorithm. This may take a minute depending on dataset size...")
    pipeline.fit(df["url"], df["label"])
    
    acc = pipeline.score(df['url'], df['label'])
    print(f"Training Complete! Model Accuracy: {acc*100:.2f}%")
    
    print(f"Saving serialized model to {MODEL_PATH}...")
    joblib.dump(pipeline, str(MODEL_PATH))
    print("The ML Model is now active and will be used by the backend automatically!")

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else None
    train_model(path)
