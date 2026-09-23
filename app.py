from flask import Flask, request
import os, time, sqlite3, base64, requests
from urllib.parse import parse_qs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)
DB_PATH = os.getenv("EGGNEST_DB", "eggnest_ssv.db")
EXPECTED_AD_UNIT = os.getenv("ADMOB_REWARDED_AD_UNIT", "")
EXPECTED_REWARD_ITEM = os.getenv("ADMOB_REWARD_ITEM", "coins")
EXPECTED_REWARD_AMOUNT = int(os.getenv("ADMOB_REWARD_AMOUNT", "10"))
MAX_AGE_MS = int(os.getenv("SSV_MAX_AGE_MS", "86400000"))
KEYS_URL = "https://www.gstatic.com/admob/reward/verifier-keys.json"

def db():
    c = sqlite3.connect(DB_PATH)
    c.execute("""CREATE TABLE IF NOT EXISTS users(
        user_id TEXT PRIMARY KEY, points INTEGER NOT NULL DEFAULT 0)""")
    c.execute("""CREATE TABLE IF NOT EXISTS ssv_rewards(
        transaction_id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
        reward_amount INTEGER NOT NULL, reward_item TEXT NOT NULL,
        ad_unit TEXT NOT NULL, timestamp_ms INTEGER NOT NULL,
        created_at INTEGER NOT NULL)""")
    c.commit()
    return c

def verify_ssv(raw):
    text = raw.decode("utf-8")
    marker = "&signature="
    if marker not in text:
        raise ValueError("missing signature")
    content, tail = text.split(marker, 1)
    if "&key_id=" not in tail:
        raise ValueError("missing key_id")
    sig_text, key_text = tail.split("&key_id=", 1)
    if "&" in key_text:
        raise ValueError("key_id must be final")
    key_id = int(key_text)
    sig = base64.urlsafe_b64decode(sig_text + "=" * (-len(sig_text) % 4))
    data = requests.get(KEYS_URL, timeout=10).json()
    item = next((x for x in data.get("keys", []) if int(x["keyId"]) == key_id), None)
    if not item:
        raise ValueError("unknown key_id")
    pem = item.get("pem")
    key = serialization.load_pem_public_key(pem.encode()) if pem else serialization.load_der_public_key(base64.b64decode(item["base64"]))
    try:
        key.verify(sig, content.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as e:
        raise ValueError("invalid signature") from e

@app.get("/")
def home():
    return "EggNest Reward V6 SSV Server is running", 200

@app.get("/health")
def health():
    return {"ok": True}, 200

@app.get("/admob/ssv")
def admob_ssv():
    try:
        verify_ssv(request.query_string)
        q = parse_qs(request.query_string.decode("utf-8"), keep_blank_values=True)
        get = lambda k: q.get(k, [None])[0]
        tx, user = get("transaction_id"), get("custom_data") or get("user_id")
        ad_unit, item = get("ad_unit"), get("reward_item")
        amount, ts = int(get("reward_amount") or 0), int(get("timestamp") or 0)
        if not tx or not user or not ad_unit:
            return "Missing required fields", 400
        if EXPECTED_AD_UNIT and ad_unit != EXPECTED_AD_UNIT:
            return "Unexpected ad unit", 400
        if item != EXPECTED_REWARD_ITEM or amount != EXPECTED_REWARD_AMOUNT:
            return "Unexpected reward configuration", 400
        if abs(int(time.time()*1000) - ts) > MAX_AGE_MS:
            return "Expired timestamp", 400
        c = db()
        try:
            c.execute("BEGIN")
            if c.execute("SELECT 1 FROM ssv_rewards WHERE transaction_id=?", (tx,)).fetchone():
                c.rollback()
                return "OK", 200
            c.execute("INSERT INTO users(user_id,points) VALUES(?,0) ON CONFLICT(user_id) DO NOTHING", (user,))
            c.execute("UPDATE users SET points=points+? WHERE user_id=?", (amount, user))
            c.execute("INSERT INTO ssv_rewards VALUES(?,?,?,?,?,?,?)",
                      (tx,user,amount,item,ad_unit,ts,int(time.time())))
            c.commit()
        finally:
            c.close()
        return "OK", 200
    except Exception as e:
        app.logger.exception("Rejected SSV: %s", e)
        return "Invalid SSV", 400

if __name__ == "__main__":
    db().close()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT","8080")))
