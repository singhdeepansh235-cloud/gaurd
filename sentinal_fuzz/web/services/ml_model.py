"""Machine Learning Phishing Classifier."""
import os
from pathlib import Path

try:
    import joblib
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

MODEL_PATH = Path(__file__).parent / "phishing_model.joblib"

_model = None

def load_model():
    global _model
    if not ML_AVAILABLE:
        return False
    if MODEL_PATH.exists():
        try:
            _model = joblib.load(str(MODEL_PATH))
            print("Successfully loaded backend ML classifier.")
            return True
        except Exception as e:
            print(f"Error loading ML model: {e}")
            return False
    return False

def predict_url(url: str) -> dict:
    """Predict phishing probability using the trained ML model.
    Returns dict: {'is_phishing': bool, 'confidence': float, 'score_impact': int} or None if no model.
    """
    global _model
    if not ML_AVAILABLE:
        return None
        
    if _model is None:
        if not load_model():
            return None
            
    try:
        # classes: 0 = Benign, 1 = Phishing
        proba = _model.predict_proba([url])[0]
        is_phish = proba[1] > 0.5
        confidence = proba[1] * 100 if is_phish else proba[0] * 100
        
        # Calculate impact on heuristic score (up to +40 for high confidence phishing)
        # If benign, we don't subtract score to stay safe (zero-trust), or maybe slightly reduce.
        score_impact = int(proba[1] * 40) if is_phish else 0
        
        return {
            "is_phishing": True if is_phish else False,
            "confidence": float(confidence),
            "score_impact": score_impact,
            "phish_probability": float(proba[1])
        }
    except Exception as e:
        print(f"ML Prediction Error: {e}")
        return None
