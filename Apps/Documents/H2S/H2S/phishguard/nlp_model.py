import argparse
import os, re, unicodedata
from pathlib import Path
import sys
import joblib, pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = PROJECT_ROOT / "phishguard" / "model.joblib"
DATA_PATH = PROJECT_ROOT / "data" / "emails.csv"   # optional: columns text,label (1 = phishing)

SEED = [
 ("Your account has been suspended. Verify your identity immediately to avoid permanent closure", 1),
 ("Urgent: unusual sign-in detected. Confirm your password within 24 hours or lose access", 1),
 ("We could not process your payment. Update your billing details now to keep your subscription", 1),
 ("Dear customer your bank account is locked. Click the link to restore access and verify your card", 1),
 ("Final notice: your parcel is on hold. Pay the small customs fee to release the delivery", 1),
 ("Action required: your mailbox is full. Log in to the portal to keep receiving email", 1),
 ("Hi, IT here. We are migrating SSO and need you to re-authenticate today through the helpdesk portal so your access is not interrupted", 1),
 ("Your KYC is expiring. Update your PAN and Aadhaar details now or your account will be blocked", 1),
 ("Congratulations, you won a gift card. Claim your reward now by entering your login and OTP", 1),
 ("Security alert: someone tried to access your account. Review activity and confirm it was you immediately", 1),
 ("Invoice attached overdue. Open the secure document and sign in with your email password to view", 1),
 ("Your salary revision letter is ready. Sign in with your work credentials to download before it expires", 1),
 ("Hi team, lunch is on Friday at 1pm in the cafeteria. Let me know if you have dietary needs", 0),
 ("Attached are the meeting notes from yesterday. Please review and add your comments by Thursday", 0),
 ("Your order has shipped and will arrive on Monday. Track it from your orders page in the app", 0),
 ("Reminder: the project demo is scheduled for next week. Slides are in the shared drive", 0),
 ("Thanks for your application. We will get back to you after the interview panel meets", 0),
 ("Here is the weekly newsletter with campus events, workshops and club announcements", 0),
 ("Can we move our call to 4pm tomorrow? I have a clash with the lab session", 0),
 ("Your receipt for the coffee purchase is below. Thank you for visiting us", 0),
 ("The assignment deadline has been extended to Sunday night. Submit through the usual course page", 0),
 ("Happy birthday! The team has booked a table for dinner on Saturday evening", 0),
 ("Please find the code review comments on your pull request. Nothing blocking, just small naming fixes", 0),
 ("Library notice: the book you reserved is available for pickup until next Friday", 0),
]


def clean(t):
    t = unicodedata.normalize("NFKC", t or "")
    t = re.sub(r"[\u200b\u200c\u200d\u2060\ufeff]", "", t)   # zero-width tricks
    t = re.sub(r"<[^>]+>", " ", t)
    t = re.sub(r"https?://\S+", " urltoken ", t)
    return t.lower()


def _load_csv(path):
    df = pd.read_csv(path)
    tcol = next(c for c in df.columns if "text" in c.lower() or "body" in c.lower())
    lcol = next(c for c in df.columns if "label" in c.lower() or "type" in c.lower() or "class" in c.lower())
    y = df[lcol].astype(str).str.lower().map(lambda v: 1 if ("phish" in v or v in ("1", "spam")) else 0)
    return df[tcol].astype(str).tolist(), y.tolist()


def train():
    if os.path.exists(DATA_PATH):
        X, y = _load_csv(DATA_PATH)
    else:
        X, y = [s for s, _ in SEED], [l for _, l in SEED]
    pipe = make_pipeline(
        TfidfVectorizer(preprocessor=clean, ngram_range=(1, 2), sublinear_tf=True, stop_words="english"),
        LogisticRegression(C=4, class_weight="balanced", max_iter=1000))
    pipe.fit(X, y)
    joblib.dump(pipe, MODEL_PATH)
    return pipe


def load_model():
    if not MODEL_PATH.is_file():
        raise FileNotFoundError(
            f"Model not found at {MODEL_PATH}. Run 'python -m phishguard.nlp_model --train' once to create it."
        )
    # Models created by the earlier script-based trainer may refer to
    # ``__main__.clean``. Supply that legacy name while loading them.
    main_module = sys.modules.get("__main__")
    if main_module is not None and not hasattr(main_module, "clean"):
        main_module.clean = clean
    return joblib.load(MODEL_PATH)


_pipe = None if __name__ == "__main__" else load_model()


def predict(text):
    if _pipe is None:
        raise RuntimeError("Model is not loaded. Start the application after running the explicit training command.")
    vec, clf = _pipe.steps[0][1], _pipe.steps[1][1]
    x = vec.transform([text])
    p = float(clf.predict_proba(x)[0][1])
    names = vec.get_feature_names_out()
    contrib = x.multiply(clf.coef_[0]).tocoo()
    top = sorted(zip(contrib.data, contrib.col), reverse=True)[:4]
    terms = [names[c] for v, c in top if v > 0 and "urltoken" not in names[c]]
    return p, terms


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Manage the PhishGraph NLP model.")
    parser.add_argument("--train", action="store_true", help="Train and save the local model explicitly.")
    args = parser.parse_args()
    if args.train:
        # Ensure pickle records the stable import path, not ``__main__.clean``.
        sys.modules["phishguard.nlp_model"] = sys.modules[__name__]
        train()
        print(f"Model trained and saved to {MODEL_PATH}")
    else:
        parser.error("training is explicit; pass --train")
