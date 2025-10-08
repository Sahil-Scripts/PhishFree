# backend/anchor.py
import os
import csv
import hashlib
from datetime import datetime
from web3 import Web3
from eth_account import Account
from dotenv import load_dotenv

# Load .env from backend folder
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

# Read environment variables
RPC_URL = os.getenv("WEB3_RPC_URL")
PRIVATE_KEY = os.getenv("WEB3_PRIVATE_KEY")

if not RPC_URL or not PRIVATE_KEY:
    raise Exception("Missing WEB3_RPC_URL or WEB3_PRIVATE_KEY in backend/.env")

# Fix private key (strip 0x if present)
if PRIVATE_KEY.startswith("0x") and len(PRIVATE_KEY) == 66:
    PRIVATE_KEY = PRIVATE_KEY[2:]

if len(PRIVATE_KEY) != 64:
    raise Exception(f"Private key must be 64 hex chars, got {len(PRIVATE_KEY)}")

# Web3 connection
w3 = Web3(Web3.HTTPProvider(RPC_URL))
if not w3.is_connected():
    raise Exception("❌ Could not connect to Ethereum RPC")

ACCOUNT = Account.from_key(PRIVATE_KEY)
ANCHORS_LOG = os.path.join(os.path.dirname(__file__), "anchors.csv")

def ensure_anchors_log():
    if not os.path.exists(ANCHORS_LOG):
        with open(ANCHORS_LOG, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "batch_hash", "tx_hash", "count", "first_idx", "last_idx"])

def compute_batch_hash(rows):
    m = hashlib.sha256()
    for r in rows:
        m.update(str(r).encode("utf-8"))
    return m.hexdigest()

def anchor_last_n(n=50, wait_for_receipt=True, test_mode=False):
    """
    Anchor the last N rows of aggregate_log.csv to Ethereum Sepolia.
    test_mode=True → only compute hash, no transaction sent.
    """
    agg_log = os.path.join(os.path.dirname(__file__), "aggregate_log.csv")
    if not os.path.exists(agg_log):
        return {"ok": False, "error": "No aggregate log file"}

    with open(agg_log, "r", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    if len(rows) <= 1:
        return {"ok": False, "error": "Not enough rows in log"}

    headers, data_rows = rows[0], rows[1:]
    last_n = data_rows[-n:] if len(data_rows) > n else data_rows
    batch_hash = compute_batch_hash(last_n)

    if test_mode:
        return {
            "ok": True,
            "test_mode": True,
            "count": len(last_n),
            "first_idx": len(data_rows) - len(last_n),
            "last_idx": len(data_rows) - 1,
            "batch_hash": batch_hash,
        }

    try:
        # Build and sign transaction
        nonce = w3.eth.get_transaction_count(ACCOUNT.address)
        tx = {
            "nonce": nonce,
            "to": ACCOUNT.address,  # self-send
            "value": 0,
            "gas": 50000,
            "gasPrice": w3.to_wei("5", "gwei"),
            "data": batch_hash.encode("utf-8"),
            "chainId": w3.eth.chain_id,
        }
        signed_tx = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)

        if wait_for_receipt:
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            status = receipt.status
        else:
            status = None

        # Save to anchors.csv
        ensure_anchors_log()
        with open(ANCHORS_LOG, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.utcnow().isoformat(),
                batch_hash,
                tx_hash.hex(),
                len(last_n),
                len(data_rows) - len(last_n),
                len(data_rows) - 1,
            ])

        return {
            "ok": True,
            "test_mode": False,
            "tx_hash": tx_hash.hex(),
            "batch_hash": batch_hash,
            "count": len(last_n),
            "first_idx": len(data_rows) - len(last_n),
            "last_idx": len(data_rows) - 1,
            "status": status,
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}

if __name__ == "__main__":
    print(anchor_last_n(n=10, test_mode=True))
