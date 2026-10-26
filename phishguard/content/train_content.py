"""
PhishGuard — Message Reader (content part)
Trains the two body-text modules and saves them:
    Word Spotter  = Naive Bayes          -> word_spotter.pkl
    Word Weigher  = Logistic Regression  -> word_weigher.pkl
Run:  python train_content.py
"""
import pandas as pd, numpy as np, joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

# 1. LOAD the dataset (text = email body, label = phishing/safe)
df = pd.read_csv("phishing_dataset.csv")
X = df["text"]
y = (df["label"] == "phishing").astype(int)      # phishing = 1, safe = 0
print(f"Loaded {len(df)} emails  ({y.sum()} phishing, {(1-y).sum()} safe)\n")

# 2. SPLIT into training and test sets
Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# 3. BUILD the two modules (same pipeline, different brain)
word_spotter = make_pipeline(TfidfVectorizer(stop_words="english"), MultinomialNB())
word_weigher = make_pipeline(TfidfVectorizer(stop_words="english"),
                             LogisticRegression(max_iter=1000))

# 4. TRAIN
word_spotter.fit(Xtr, ytr)
word_weigher.fit(Xtr, ytr)

# 5. TEST — how good is each?
for name, model in [("WORD SPOTTER (Naive Bayes)", word_spotter),
                    ("WORD WEIGHER (Logistic Regression)", word_weigher)]:
    pred = model.predict(Xte)
    print("="*55); print(name)
    print(classification_report(yte, pred, target_names=["safe","phishing"], zero_division=0))
    tn, fp, fn, tp = confusion_matrix(yte, pred).ravel()
    print(f"  correct phishing (TP): {tp}   missed (FN): {fn}")
    print(f"  correct safe (TN): {tn}   false alarms (FP): {fp}\n")

# 6. SHOW what the Word Weigher learned (top phishing words)
vec = word_weigher.named_steps["tfidfvectorizer"]
clf = word_weigher.named_steps["logisticregression"]
words = np.array(vec.get_feature_names_out())
top = words[np.argsort(clf.coef_[0])[-12:]][::-1]
print("Top phishing words the Word Weigher learned:")
print("  ", ", ".join(top), "\n")

# 7. SAVE both trained models for the product to use
joblib.dump(word_spotter, "word_spotter.pkl")
joblib.dump(word_weigher, "word_weigher.pkl")
print("Saved: word_spotter.pkl  and  word_weigher.pkl")
