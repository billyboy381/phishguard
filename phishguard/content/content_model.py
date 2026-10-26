"""Message Reader - the ML content module (the 'Word Weigher', Logistic Regression).

Loads a trained model (word_weigher.pkl) if present; otherwise trains one from the
bundled phishing_dataset.csv on first use and caches it. If scikit-learn is not
installed, the module degrades gracefully to an INFO (skipped) result.
"""
import os
from phishguard.core.models import ModuleReport, Severity
from phishguard.core.eml import get_body_text

_HERE = os.path.dirname(__file__)
_PKL = os.path.join(_HERE, "word_weigher.pkl")
_CSV = os.path.join(_HERE, "phishing_dataset.csv")
_MODEL = None
_LOADED = False


def _get_model():
    global _MODEL, _LOADED
    if _LOADED:
        return _MODEL
    _LOADED = True
    try:
        import joblib
    except Exception:
        _MODEL = None
        return None
    # 1) use a pre-trained model if we have one
    if os.path.exists(_PKL):
        try:
            _MODEL = joblib.load(_PKL)
            return _MODEL
        except Exception:
            pass
    # 2) otherwise train from the bundled dataset
    try:
        import pandas as pd
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import make_pipeline
        df = pd.read_csv(_CSV)
        X = df["text"]
        y = (df["label"] == "phishing").astype(int)
        model = make_pipeline(TfidfVectorizer(stop_words="english"),
                              LogisticRegression(max_iter=1000))
        model.fit(X, y)
        try:
            joblib.dump(model, _PKL)
        except Exception:
            pass
        _MODEL = model
    except Exception:
        _MODEL = None
    return _MODEL


class ContentDetector:
    """Judges whether the email body text reads like phishing."""

    def name(self) -> str:
        return "content_ml"

    def analyze(self, msg) -> ModuleReport:
        model = _get_model()
        body = get_body_text(msg)

        if model is None:
            return ModuleReport(module=self.name(), passed=True, severity=Severity.INFO,
                                details="Content ML unavailable (install scikit-learn, pandas, joblib).")
        if not body:
            return ModuleReport(module=self.name(), passed=True, severity=Severity.INFO,
                                details="No body text to analyze.")

        prob = float(model.predict_proba([body])[0][1])
        pct = round(prob * 100, 1)
        if prob >= 0.85:
            return ModuleReport(module=self.name(), passed=False, severity=Severity.HIGH,
                                details=f"Body text reads like phishing ({pct}% confidence).")
        if prob >= 0.5:
            return ModuleReport(module=self.name(), passed=False, severity=Severity.WARNING,
                                details=f"Body text is somewhat suspicious ({pct}% phishing).")
        return ModuleReport(module=self.name(), passed=True, severity=Severity.INFO,
                            details=f"Body text looks normal ({pct}% phishing).")
