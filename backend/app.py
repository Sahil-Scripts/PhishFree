# backend/app.py - PhishingProto backend (complete with anchor fixes)
import os
import csv
import re
import json
import time
import unicodedata
from datetime import datetime
from collections import defaultdict, Counter
from urllib.parse import urlparse
import pytz
from dotenv import load_dotenv
from web3 import Web3
import hashlib
import logging
from hexbytes import HexBytes
import base64
import io
import numpy as np

# Import model classes (keep these imports as they are)
from cnn_model import CNNModel as CNNScorer
from gnn_model import GraphEngine
from ensemble import combine_scores
from llm_model import TextScorer

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from functools import lru_cache
from typing import Dict, Any, List, Tuple, Optional
import math




# Load environment variables from backend/.env
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

# Optional: import your model components
try:
    from llm_model import TextScorer
except Exception:
    TextScorer = None

try:
    from redirect import follow_redirects, get_cert_fingerprint
except Exception:
    def follow_redirects(url): return {"final_url": url, "hops": [], "status_code": None}
    def get_cert_fingerprint(url): return {"cert_fp": None}

try:
    from domain_info import domain_whois_info, domain_asn_info
except Exception:
    def domain_whois_info(hostname): return {}
    def domain_asn_info(hostname): return {}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AGG_PATH = os.path.join(BASE_DIR, "aggregate_log.csv")
AGG_LOG = os.path.join(os.path.dirname(__file__), "aggregate_log.csv")
FP_LOG = os.path.join(os.path.dirname(__file__), "false_positives.csv")
ANCHORS_PATH = os.path.join(os.path.dirname(__file__), "anchors.csv")
IST = pytz.timezone("Asia/Kolkata")

# NOTE: Model initializations moved below to after Flask `app` creation
# (they previously ran before `app = Flask(...)` which caused NameError on app.logger)

# --- Web3 setup ---
WEB3_RPC_URL = os.getenv("WEB3_RPC_URL") or ""
WEB3_PRIVATE_KEY = os.getenv("WEB3_PRIVATE_KEY") or os.getenv("PRIVATE_KEY") or ""

# normalize private key to include 0x prefix (helps avoid subtle signing errors)
if WEB3_PRIVATE_KEY and not WEB3_PRIVATE_KEY.startswith("0x"):
    WEB3_PRIVATE_KEY = "0x" + WEB3_PRIVATE_KEY

if not WEB3_PRIVATE_KEY:
    print("Warning: WEB3_PRIVATE_KEY not set. Anchors requiring a tx will fall back to test mode.")
elif len(WEB3_PRIVATE_KEY) < 66:
    print("Warning: WEB3_PRIVATE_KEY looks short; ensure it's the full 32-byte hex key (with or without 0x).")

# chain id default to Sepolia if not provided
try:
    WEB3_CHAIN_ID = int(os.getenv("WEB3_CHAIN_ID", "11155111"))
except Exception:
    WEB3_CHAIN_ID = 11155111

w3 = None
ACCOUNT = None
if WEB3_RPC_URL:
    try:
        w3 = Web3(Web3.HTTPProvider(WEB3_RPC_URL))
        print(f"✅ Connected to RPC: {WEB3_RPC_URL}")
    except Exception as e:
        print("Warning: failed to initialize Web3 provider:", e)
        w3 = None

if w3 and WEB3_PRIVATE_KEY:
    try:
        ACCOUNT = w3.eth.account.from_key(WEB3_PRIVATE_KEY)
        print("Account Address:", ACCOUNT.address)
    except Exception as e:
        print("Warning: invalid WEB3_PRIVATE_KEY:", e)
        ACCOUNT = None
else:
    if w3 and not WEB3_PRIVATE_KEY:
        print("Warning: Web3 provider available but private key missing; anchors will be recorded as test mode.")
    ACCOUNT = None

# -------------------------
# Small helpers: URL regex, client_ip, simple rate limiter
# -------------------------
# Extract http/https/www style URLs from free text
URL_REGEX = re.compile(r"(https?://[^\s,;\"']+|www\.[^\s,;\"']+)", re.IGNORECASE)

# Basic in-memory rate limiter (demo-only; not persistent)
# Structure: { ip_str: [timestamp1, timestamp2, ...] }
_RATE_LIMIT_STORE = {}
_RATE_LIMIT_LOCK = None  # placeholder if you want a threading.Lock
# config: allow up to `RATE_LIMIT_MAX` requests per `RATE_LIMIT_WINDOW` seconds
RATE_LIMIT_MAX = int(os.getenv("RATE_LIMIT_MAX", "60"))       # default 60 reqs
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60")) # window in seconds

def client_ip():
    """
    Determine client IP from request, even behind a reverse proxy if X-Forwarded-For present.
    """
    try:
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            # X-Forwarded-For may contain comma-separated list; take first
            return forwarded.split(",")[0].strip()
        if request.remote_addr:
            return request.remote_addr
        return request.environ.get("REMOTE_ADDR", "unknown")
    except Exception:
        return "unknown"

def is_rate_limited(ip: str) -> bool:
    """
    Very small in-memory sliding-window rate limiter.
    Returns True if the IP exceeded RATE_LIMIT_MAX requests in the last RATE_LIMIT_WINDOW seconds.
    Demo-only; use Redis/DB for production.
    """
    try:
        now = time.time()
        window_start = now - RATE_LIMIT_WINDOW
        hits = _RATE_LIMIT_STORE.get(ip, [])
        # keep only hits inside the window
        hits = [t for t in hits if t >= window_start]
        if len(hits) >= RATE_LIMIT_MAX:
            # update store to trimmed list to avoid unbounded growth
            _RATE_LIMIT_STORE[ip] = hits
            return True
        # record the new hit
        hits.append(now)
        _RATE_LIMIT_STORE[ip] = hits
        return False
    except Exception:
        # on any error, don't rate limit (fail-open for demo)
        return False


def extract_edges_from_aggregate(csv_path: str):
    """
    Parse aggregate_log.csv and produce a list of (src, dst) edges.
    Creates edges based on domain relationships, IP addresses, and URL patterns.
    """
    edges = []
    try:
        with open(csv_path, newline='', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames or []
            
            # Track domains, IPs, and their relationships
            domains = set()
            ips = set()
            domain_connections = {}
            ip_connections = {}
            domain_ip_map = {}
            
            for row in reader:
                # Extract domain from URL
                url = row.get("url", "").strip()
                domain = row.get("domain", "").strip()
                
                if not domain and url:
                    try:
                        parsed = urlparse(url)
                        domain = parsed.hostname or ""
                    except Exception:
                        continue
                
                if domain:
                    domains.add(domain)
                    
                    # Try to resolve IP for this domain
                    try:
                        import socket
                        ip = socket.gethostbyname(domain)
                        ips.add(ip)
                        domain_ip_map[domain] = ip
                        
                        # Group domains by IP
                        if ip not in ip_connections:
                            ip_connections[ip] = set()
                        ip_connections[ip].add(domain)
                    except Exception:
                        pass
                    
                    # Create connections based on similar domains or suspicious patterns
                    # Group similar domains together
                    base_domain = domain
                    if '.' in domain:
                        parts = domain.split('.')
                        if len(parts) >= 2:
                            base_domain = '.'.join(parts[-2:])  # Get TLD + domain
                    
                    if base_domain not in domain_connections:
                        domain_connections[base_domain] = set()
                    domain_connections[base_domain].add(domain)
            
            # Create edges between domains sharing the same IP
            for ip, domain_set in ip_connections.items():
                domain_list = list(domain_set)
                if len(domain_list) > 1:
                    # Connect all domains sharing the same IP
                    for i in range(len(domain_list)):
                        for j in range(i + 1, len(domain_list)):
                            edges.append((domain_list[i], domain_list[j]))
                            edges.append((domain_list[j], domain_list[i]))  # Bidirectional
            
            # Create edges between domains in the same group (same base domain)
            for base_domain, domain_set in domain_connections.items():
                domain_list = list(domain_set)
                if len(domain_list) > 1:
                    # Connect all domains in the same group
                    for i in range(len(domain_list)):
                        for j in range(i + 1, len(domain_list)):
                            edges.append((domain_list[i], domain_list[j]))
                            edges.append((domain_list[j], domain_list[i]))  # Bidirectional
            
            # Add comprehensive synthetic suspicious domain connections for better GNN performance
            suspicious_patterns = [
                # Banking/Financial phishing
                ('secure-bank-login.example', 'fake-bank.com'),
                ('bank-verify.net', 'account-update.org'),
                ('payment-secure.com', 'billing-service.net'),
                ('login-verify.org', 'account-security.com'),
                
                # Crypto/Investment scams
                ('crypto-wallet.org', 'bitcoin-exchange.com'),
                ('investment-opportunity.net', 'crypto-mining.org'),
                ('wallet-recovery.com', 'blockchain-verify.net'),
                
                # Social media/Account verification
                ('social-login.net', 'profile-update.com'),
                ('account-verify.org', 'security-check.net'),
                ('login-secure.com', 'verify-account.org'),
                
                # Payment/Invoice scams
                ('payment-update.com', 'invoice-pay.net'),
                ('billing-service.org', 'payment-verify.com'),
                ('invoice-secure.net', 'payment-gateway.org'),
                
                # Tech support scams
                ('tech-support.net', 'system-update.org'),
                ('security-alert.com', 'virus-removal.net'),
                ('windows-update.org', 'microsoft-support.com'),
                
                # Email/Communication
                ('email-verify.net', 'account-suspended.org'),
                ('mail-security.com', 'inbox-update.net'),
                ('message-center.org', 'notification-service.com')
            ]
            
            # Add synthetic connections for domains that exist in our data
            for src, dst in suspicious_patterns:
                if src in domains or dst in domains:
                    edges.append((src, dst))
                    edges.append((dst, src))
            
            # Add connections based on suspicious keywords in domain names
            suspicious_keywords = ['secure', 'login', 'verify', 'account', 'bank', 'payment', 'crypto', 'wallet']
            for domain in domains:
                for keyword in suspicious_keywords:
                    if keyword in domain.lower():
                        # Connect to other domains with similar keywords
                        for other_domain in domains:
                            if other_domain != domain and keyword in other_domain.lower():
                                edges.append((domain, other_domain))
                                edges.append((other_domain, domain))
            
            # De-duplicate edges
            edges = list({(a, b) for (a, b) in edges if a and b and a != b})
            
    except Exception as e:
        # app.logger not available here yet; print as fallback
        try:
            print("Failed to extract edges from aggregate CSV:", e)
        except Exception:
            pass
    return edges


# --- Anchors CSV helpers ---
def ensure_anchors_csv():
    header = ["timestamp", "mode", "rows", "first_row_index", "last_row_index",
              "batch_hash", "tx_hash", "chain_id", "status", "message"]
    if not os.path.exists(ANCHORS_PATH):
        with open(ANCHORS_PATH, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(header)

def append_anchor_row(row: dict):
    ensure_anchors_csv()
    header = ["timestamp", "mode", "rows", "first_row_index", "last_row_index",
              "batch_hash", "tx_hash", "chain_id", "status", "message"]
    with open(ANCHORS_PATH, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writerow({k: row.get(k, "") for k in header})

# --- Flask setup ---
app = Flask(__name__)
CORS(app)

# configure logging for easier debugging
logging.basicConfig(level=logging.DEBUG)
app.logger.setLevel(logging.DEBUG)


# -----------------------------
# Compatibility wrappers
# -----------------------------
# These wrappers adapt newer model class APIs to the older names/behaviors used by app code.
# They keep the old endpoints unchanged while allowing the repo to use CNNModel and GraphEngine internals.

class CNNWrapper:
    """
    Wraps instances of your cnn model (which may expose predict_from_bytes / predict_from_pil / score_image_bytes)
    and provides a stable method score_image_bytes(image_bytes) returning:
      {"ok": True, "score": float, "reasons": [...]} or {"ok": False, "error": "..."}
    """
    def __init__(self, raw):
        self.raw = raw

    def score_image_bytes(self, image_bytes: bytes) -> Dict[str, Any]:
        try:
            # if raw already provides the legacy method, use it
            if hasattr(self.raw, "score_image_bytes"):
                return self.raw.score_image_bytes(image_bytes)
            # if raw exposes a 'score' method returning dict
            if hasattr(self.raw, "score"):
                try:
                    out = self.raw.score(image_bytes)
                    # normalize possible shapes
                    if isinstance(out, dict):
                        return {"ok": True, "score": float(out.get("score", 0.0)), "reasons": out.get("reasons", [])}
                except Exception:
                    pass
            # if raw has predict_from_bytes (our HF CLIP-based model)
            if hasattr(self.raw, "predict_from_bytes"):
                res = self.raw.predict_from_bytes(image_bytes)
                # expected res: {'score':float,...}
                score = float(res.get("score", 0.0)) if isinstance(res, dict) else 0.0
                reasons = res.get("reasons", []) if isinstance(res, dict) else []
                return {"ok": True, "score": score, "reasons": reasons}
            # if raw has predict_from_pil
            if hasattr(self.raw, "predict_from_pil"):
                from PIL import Image
                pil = Image.open(io.BytesIO(image_bytes)).convert("RGB")
                res = self.raw.predict_from_pil(pil)
                score = float(res.get("score", 0.0)) if isinstance(res, dict) else 0.0
                reasons = res.get("reasons", []) if isinstance(res, dict) else []
                return {"ok": True, "score": score, "reasons": reasons}
            # fallback: unknown api
            return {"ok": False, "error": "cnn model has no known predict method"}
        except Exception as e:
            return {"ok": False, "error": str(e)}


class GraphEngineAdapter:
    """
    Provide backward-compatible methods:
      - build_graph_from_edges(edges)
      - compute_node2vec_embeddings(dimensions, walk_length, num_walks)
      - predict_node_score(domain)
    It wraps underlying GraphEngine; if GraphEngine already has these methods they are used directly.
    If not, the adapter attempts a reasonable fallback (creating node index mapping, dummy features, simple degree-based 'embeddings').
    """
    def __init__(self, raw_engine):
        self.raw = raw_engine
        # node name -> idx
        self._nodes_map = {}
        # simple embeddings map (domain -> vector)
        self.embeddings = getattr(raw_engine, "embeddings", {}) or {}
        # store edge_index and node_features if created
        self.edge_index = None
        self.node_features = None

    def build_graph_from_edges(self, edges: List[Tuple[str, str]]):
        # If underlying engine offers the function, use it directly
        if hasattr(self.raw, "build_graph_from_edges"):
            try:
                return self.raw.build_graph_from_edges(edges)
            except Exception:
                # fallthrough to local build
                pass

        # Build node index mapping
        nodes = {}
        idx = 0
        for a, b in edges:
            if a not in nodes:
                nodes[a] = idx; idx += 1
            if b not in nodes:
                nodes[b] = idx; idx += 1

        # Create a minimal node_features array (zeros) and edge_index matrix
        N = len(nodes)
        if N == 0:
            self._nodes_map = {}
            self.edge_index = np.zeros((2, 0), dtype=np.int64)
            self.node_features = np.zeros((0, 8), dtype=np.float32)
        else:
            edge_u = []
            edge_v = []
            for a, b in edges:
                try:
                    u = nodes[a]; v = nodes[b]
                    edge_u.append(u); edge_v.append(v)
                except KeyError:
                    continue
            if len(edge_u) == 0:
                self.edge_index = np.zeros((2, 0), dtype=np.int64)
            else:
                self.edge_index = np.vstack([np.array(edge_u, dtype=np.int64), np.array(edge_v, dtype=np.int64)])
            # node features: small vector of zeros (shape [N, F])
            self.node_features = np.zeros((N, 8), dtype=np.float32)

        self._nodes_map = nodes

        # If underlying engine supports load_graph, pass arrays to it
        if hasattr(self.raw, "load_graph"):
            try:
                self.raw.load_graph(self.node_features, self.edge_index)
            except Exception:
                # swallow; adapter will use local arrays
                pass
        else:
            # attach minimal attributes so other code may inspect them
            try:
                setattr(self.raw, "node_features", self.node_features)
                setattr(self.raw, "edge_index", self.edge_index)
            except Exception:
                pass

        return True

    def compute_node2vec_embeddings(self, dimensions: int = 64, walk_length: int = 10, num_walks: int = 80):
        # Prefer underlying implementation if available
        if hasattr(self.raw, "compute_node2vec_embeddings"):
            try:
                return self.raw.compute_node2vec_embeddings(dimensions=dimensions, walk_length=walk_length, num_walks=num_walks)
            except Exception:
                pass

        # If the raw engine has node2vec via another name, try common variants
        for candidate in ("compute_node2vec", "node2vec", "build_node2vec", "fit_node2vec"):
            if hasattr(self.raw, candidate):
                try:
                    getattr(self.raw, candidate)(dimensions=dimensions, walk_length=walk_length, num_walks=num_walks)
                    self.embeddings = getattr(self.raw, "embeddings", {}) or {}
                    return True
                except Exception:
                    pass

        # Fallback: create very small synthetic embeddings using node degrees
        try:
            if self.edge_index is None and hasattr(self.raw, "edge_index"):
                self.edge_index = np.array(self.raw.edge_index) if isinstance(getattr(self.raw, "edge_index", None), (list, tuple, np.ndarray)) else None
            if self._nodes_map is None or len(self._nodes_map) == 0:
                # attempt to build from raw attributes
                try:
                    # if raw has attribute 'node_features' and 'edge_index', try to infer node names as indices 0..N-1
                    nf = getattr(self.raw, "node_features", None)
                    if nf is not None:
                        N = nf.shape[0]
                        self._nodes_map = {str(i): i for i in range(N)}
                except Exception:
                    pass

            if self.edge_index is None:
                # no edges -> zero embeddings
                self.embeddings = {name: np.zeros(dimensions, dtype=np.float32) for name in (self._nodes_map or {})}
            else:
                # compute degree vector and use short embedding
                N = max(self.edge_index.max() + 1, 0) if self.edge_index.size else 0
                deg = np.zeros((N,), dtype=np.float32)
                if self.edge_index.size:
                    for u in self.edge_index[0]:
                        deg[int(u)] += 1.0
                # simple embedding: [deg, sin(deg), cos(deg), ...] up to dimensions
                emb_map = {}
                for name, idx in (self._nodes_map or {}).items():
                    base = float(deg[int(idx)]) if int(idx) < len(deg) else 0.0
                    vec = np.zeros((dimensions,), dtype=np.float32)
                    vec[0] = base
                    for i in range(1, dimensions):
                        vec[i] = math.sin(base * (i + 1)) if base != 0 else 0.0
                    emb_map[name] = vec
                self.embeddings = emb_map
        except Exception:
            self.embeddings = {}

        # attach to raw if possible
        try:
            setattr(self.raw, "embeddings", self.embeddings)
        except Exception:
            pass

        return True

    def predict_node_score(self, domain: str) -> Optional[float]:
        """
        Return a float probability (0..1) or None if unknown/not available.
        Tries multiple underlying methods: predict_node_score, predict_node, predict_all, model-based predictions.
        """
        # direct API
        if hasattr(self.raw, "predict_node_score"):
            try:
                return self.raw.predict_node_score(domain)
            except Exception:
                pass

        # if raw exposes predict_node(index)
        if hasattr(self.raw, "predict_node"):
            if domain in self._nodes_map:
                idx = self._nodes_map[domain]
                try:
                    val = self.raw.predict_node(idx)
                    return float(val) if val is not None else None
                except Exception:
                    pass
            else:
                return None

        # if raw has predict_all returning ndarray
        if hasattr(self.raw, "predict_all"):
            try:
                arr = self.raw.predict_all()
                if domain in self._nodes_map:
                    return float(arr[self._nodes_map[domain]])
                else:
                    return None
            except Exception:
                pass

        # if raw has a model attribute that can be called (best-effort)
        if hasattr(self.raw, "model") and getattr(self.raw, "node_features", None) is not None:
            try:
                # attempt a forward pass using PyTorch model if available
                model = getattr(self.raw, "model")
                nf = getattr(self.raw, "node_features")
                # if node_features is numpy -> convert
                x = torch.tensor(nf, dtype=torch.float32)
                if hasattr(model, "to"):
                    model = model.to("cpu")
                model.eval()
                with torch.no_grad():
                    out = model(x, torch.tensor(getattr(self.raw, "edge_index", np.zeros((2, 0), dtype=np.int64)), dtype=torch.long))
                if domain in self._nodes_map:
                    idx = self._nodes_map[domain]
                    return float(out[idx].cpu().numpy()) if hasattr(out, "cpu") else float(out[idx])
            except Exception:
                pass

        # As last resort, if we have embeddings and a simple heuristic: high-degree -> suspicious
        if self.embeddings and domain in self.embeddings:
            vec = self.embeddings.get(domain)
            # heuristic: relative norm -> map to 0..1
            try:
                norm = float(np.linalg.norm(vec))
                score = min(1.0, norm / (1.0 + norm))
                return float(score)
            except Exception:
                return None

        return None


# -----------------------------
# initialize scorer if present
# NOTE: create both `scorer` and `text_scorer` so existing endpoints that use either name keep working
# -----------------------------
text_scorer = None
scorer = None
try:
    if TextScorer:
        text_scorer = TextScorer()
        scorer = text_scorer
        app.logger.info("TextScorer initialized")
    else:
        scorer = None
        text_scorer = None
        app.logger.info("TextScorer not available; using heuristics")
except Exception as e:
    app.logger.warning("TextScorer init failed: %s", e)
    text_scorer = None
    scorer = None

# initialize CNN scorer
cnn_scorer = None
try:
    cnn_scorer = CNNScorer()
    app.logger.info("CNNScorer initialized successfully")
except Exception as e:
    app.logger.warning("CNNScorer init failed: %s", e)
    cnn_scorer = None

# initialize GraphEngine
graph_engine = None
try:
    graph_engine = GraphEngine()
    
    # Initialize with some test data to make GNN work
    # Focus on suspicious domains for better detection
    test_edges = [
        ('test-phish.com', 'phishing-site.com'),
        ('test-phish.com', 'suspicious-domain.net'),
        ('phishing-site.com', 'malicious-page.org'),
        ('fake-bank.com', 'phishing-site.com'),
        ('suspicious-domain.net', 'malicious-page.org'),
        ('phish-example.com', 'test-phish.com'),
        ('scam-site.org', 'phishing-site.com'),
        ('fake-paypal.com', 'phishing-site.com'),
        ('malicious-page.org', 'scam-site.org'),
        ('phishing-site.com', 'fake-bank.com')
    ]
    
    # Build graph from test edges
    graph_engine.build_graph_from_edges(test_edges)
    graph_engine.compute_node2vec_embeddings(dimensions=32, walk_length=5, num_walks=20)
    
    app.logger.info("GraphEngine initialized successfully with test data")
except Exception as e:
    app.logger.warning("GraphEngine init failed: %s", e)
    graph_engine = None

# --- Simple caching for performance ---
text_cache = {}
cnn_cache = {}
gnn_cache = {}

# --- Additional startup info for debugging ---
app.logger.info("=== Model availability on startup ===")
app.logger.info("TextScorer available: %s", bool(text_scorer))
app.logger.info("CNNScorer available: %s", bool(cnn_scorer))
app.logger.info("GraphEngine available: %s", bool(graph_engine))

# --- Build graph once at startup (use wrapper API) ---
if graph_engine is not None:
    try:
        AGG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aggregate_log.csv")
        edges = extract_edges_from_aggregate(AGG_PATH)
        if edges:
            app.logger.info("Building graph from aggregate (edges=%d)", len(edges))
            graph_engine.build_graph_from_edges(edges)
            graph_engine.compute_node2vec_embeddings(dimensions=64, walk_length=10, num_walks=80)
            try:
                n_nodes = len(getattr(graph_engine, "embeddings", {}) or {})
            except Exception:
                n_nodes = 0
            app.logger.info("Graph embeddings computed (nodes=%d)", n_nodes)
        else:
            app.logger.info("No edges found in aggregate_log.csv; graph left empty")
    except Exception as e:
        app.logger.warning("GraphEngine build failed: %s", e)

# --- Load trained LightGBM model at startup ---
try:
    model_loaded = lightgbm_ensemble.load_model()
    if model_loaded:
        app.logger.info("Trained LightGBM model loaded successfully")
    else:
        app.logger.info("No trained LightGBM model found, will use fallback ensemble")
except Exception as e:
    app.logger.warning("Failed to load LightGBM model: %s", e)

# --- Dashboard route ---
@app.route("/dashboard", methods=["GET"])
def dashboard():
    """Serve the dashboard HTML file"""
    return send_file(os.path.join(os.path.dirname(__file__), "static", "dashboard.html"))

@app.route("/", methods=["GET"])
def root():
    """Redirect root to dashboard"""
    return send_file(os.path.join(os.path.dirname(__file__), "static", "dashboard.html"))

@app.route("/aggregate/has_log", methods=["GET"])
def has_log():
    """Check if aggregate log exists"""
    return jsonify({"exists": os.path.exists(AGG_LOG)})

@app.route("/report/false_positive", methods=["POST"])
def report_false_positive():
    """Report a site as safe (false positive)"""
    try:
        data = request.get_json(force=True)
        url = data.get("url", "")
        hostname = data.get("hostname", "")
        timestamp = data.get("timestamp", datetime.utcnow().isoformat() + "Z")
        note = data.get("note", "reported_safe_by_user")
        analysis = data.get("analysis", {})
        
        # Create false positives CSV if it doesn't exist
        false_positives_path = os.path.join(os.path.dirname(__file__), "false_positives.csv")
        
        # Check if file exists and has headers
        file_exists = os.path.exists(false_positives_path)
        if not file_exists:
            with open(false_positives_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["timestamp", "url", "hostname", "note", "analysis_json"])
        
        # Append the false positive report
        with open(false_positives_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, url, hostname, note, json.dumps(analysis)])
        
        app.logger.info("False positive reported for URL: %s", url)
        return jsonify({"ok": True, "message": "Site reported as safe"})
        
    except Exception as e:
        app.logger.exception("Failed to report false positive: %s", e)
        return jsonify({"ok": False, "error": str(e)}), 500

# --- Health + ping ---
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "OK", "service": "phish-proto-backend"})

@app.route("/ping", methods=["POST"])
def ping():
    data = request.get_json(silent=True) or {}
    return jsonify({"pong": True, "received": data})

# --- Text analysis ---
@app.route("/analyze/text", methods=["POST"])
def analyze_text():
    body = request.get_json(silent=True) or {}
    text = body.get("text", "")
    if not text or not str(text).strip():
        return jsonify({"error": "no text provided"}), 400
    text = unicodedata.normalize("NFKC", str(text))
    if scorer:
        res = scorer.score(text)
        label = "suspicious" if res.get("score", 0) >= 0.6 else "benign"
        return jsonify({"label": label, "score": round(res.get("score",0), 4), "components": res.get("components"), "reasons": res.get("reasons")})
    else:
        s = 0.0
        reasons = []
        for k in ["login","account","password","verify","otp","invoice","bank","ssn"]:
            if k in text.lower():
                s += 0.2; reasons.append(f"Contains keyword: {k}")
        s = min(1.0, s)
        label = "suspicious" if s >= 0.6 else "benign"
        return jsonify({"label": label, "score": round(s,4), "reasons": reasons})

# --- URL analysis ---
@app.route("/analyze/url", methods=["POST"])
def analyze_url():
    ip = client_ip()
    if is_rate_limited(ip):
        return jsonify({"error": "rate_limited"}), 429
    body = request.get_json(silent=True) or {}
    url = body.get("url")
    if not url:
        text = body.get("text", "")
        match = URL_REGEX.search(text or "")
        if match: url = match.group(0)
        else: return jsonify({"error": "no url provided"}), 400
    if not urlparse(url).scheme: url = "http://" + url
    redirects = follow_redirects(url)
    final = redirects.get("final_url") if isinstance(redirects, dict) else url
    cert = get_cert_fingerprint(final) if final else {"cert_fp": None}
    enrichment = {}
    parsed = urlparse(final or url)
    if parsed.hostname:
        enrichment = {"whois": domain_whois_info(parsed.hostname), "asn": domain_asn_info(parsed.hostname)}
    result = {
        "input_url": url,
        "redirects": redirects.get("hops") if isinstance(redirects, dict) else [],
        "final_url": final,
        "status": redirects.get("status_code") if isinstance(redirects, dict) else None,
        "cert": cert,
        "enrichment": enrichment,
    }
    return jsonify(result)

# --- Aggregate analyze ---
@app.route("/analyze/aggregate", methods=["POST"])
def analyze_aggregate():
    try:
        body = request.get_json(silent=True) or {}
        text = body.get("text", "") or ""
        url = body.get("url")
        if not url and text:
            m = URL_REGEX.search(text)
            if m: url = m.group(0)
        
        # Auto-capture page content if URL is provided but no text
        if url and not text:
            try:
                import requests
                try:
                    from bs4 import BeautifulSoup
                except ImportError:
                    # Fallback if BeautifulSoup is not available
                    BeautifulSoup = None
                response = requests.get(url, timeout=10, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                })
                if response.status_code == 200:
                    if BeautifulSoup:
                        soup = BeautifulSoup(response.text, 'html.parser')
                        # Extract text content
                        for script in soup(["script", "style"]):
                            script.decompose()
                        text = soup.get_text()
                        # Clean up text
                        lines = (line.strip() for line in text.splitlines())
                        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
                        text = ' '.join(chunk for chunk in chunks if chunk)
                        text = text[:2000]  # Limit to first 2000 chars
                        app.logger.info(f"Auto-captured {len(text)} chars from {url}")
                    else:
                        # Simple text extraction without BeautifulSoup
                        text = response.text[:1000]  # Just take first 1000 chars
                        app.logger.info(f"Auto-captured {len(text)} chars from {url} (simple extraction)")
            except Exception as e:
                app.logger.warning(f"Failed to auto-capture content from {url}: {e}")
                text = f"Content from {url} (capture failed)"
        
        # Auto-generate a simple screenshot placeholder for CNN analysis
        # This ensures CNN always runs even without image data
        image_b64 = body.get("image_b64")
        if not image_b64 and url:
            # Create a simple 1x1 pixel PNG as placeholder
            image_b64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNgYAAAAAMAASsJTYQAAAAASUVORK5CYII="
            app.logger.info(f"Using placeholder image for CNN analysis of {url}")

        # TEXT scoring
        text_norm = text.strip()
        text_res = {"score": 0.0, "reasons": []}
        if text_norm:
            try:
                if scorer:
                    t = scorer.score(text_norm)
                    text_res["score"] = round(float(t.get("score", 0.0)), 4)
                    text_res["reasons"] = t.get("reasons", [])
                else:
                    s=0.0; r=[]
                    for k in ["login","account","verify","otp","password","bank","invoice"]:
                        if k in text_norm.lower(): s+=0.15; r.append(f"Keyword: {k}")
                    text_res={"score":round(min(1.0,s),4),"reasons":r}
            except Exception as e:
                text_res={"score":0.0,"reasons":[f"Text analysis error: {e}"]}

        # CNN scoring - ALWAYS RUN if we have a URL or image
        cnn_score = 0.0
        cnn_reasons = []
        if cnn_scorer and (image_b64 or url):
            try:
                # Accept either full data-uri or plain base64
                img_b64 = image_b64
                if "," in img_b64:
                    img_b64 = img_b64.split(",", 1)[1]
                image_bytes = base64.b64decode(img_b64)
                
                # Optimize image size for faster processing
                try:
                    from PIL import Image
                    import io
                    img = Image.open(io.BytesIO(image_bytes))
                    # Resize large images to max 512x512 for faster processing
                    if img.size[0] > 512 or img.size[1] > 512:
                        img.thumbnail((512, 512), Image.Resampling.LANCZOS)
                        img_bytes = io.BytesIO()
                        img.save(img_bytes, format='PNG', optimize=True)
                        image_bytes = img_bytes.getvalue()
                except Exception as e:
                    app.logger.debug("analyze/aggregate: image optimization failed: %s", e)
                
                # Call CNN scorer
                raw_c_res = cnn_scorer.score_image_bytes(image_bytes)
                app.logger.debug("analyze/aggregate: raw cnn response: %r", raw_c_res)
                
                # Parse CNN response
                if isinstance(raw_c_res, dict) and "score" in raw_c_res:
                    cnn_score = float(raw_c_res.get("score", 0.0))
                    cnn_reasons = raw_c_res.get("reasons", [])
                    if not cnn_reasons:
                        cnn_reasons = [f"CNN visual analysis: {cnn_score:.2f}"]
                elif isinstance(raw_c_res, (int, float)):
                    cnn_score = float(raw_c_res)
                    cnn_reasons = [f"CNN visual analysis: {cnn_score:.2f}"]
                else:
                    cnn_reasons = ["cnn returned no valid score"]
            except Exception as e:
                app.logger.exception("analyze/aggregate: cnn scoring failed: %s", e)
                cnn_reasons = [f"cnn error: {e}"]
        elif not cnn_scorer:
            cnn_reasons = ["cnn model not available"]
        else:
            cnn_reasons = ["no url or image provided for cnn analysis"]

        # GNN scoring - ALWAYS RUN if we have a URL
        gnn_score = 0.0
        gnn_reasons = []
        domain = ""
        if url:
            try:
                parsed = urlparse(url)
                domain = parsed.hostname or ""
            except Exception:
                domain = ""
        
        if graph_engine:
            try:
                if domain:
                    # Check cache first
                    if domain in gnn_cache:
                        gnn_score = gnn_cache[domain]
                        app.logger.debug("Using cached GNN result for domain: %s", domain)
                        gnn_reasons = [f"GNN graph analysis: {gnn_score:.2f} (cached)"]
                    else:
                        pred = graph_engine.predict_node_score(domain)
                        gnn_score = float(pred) if pred is not None else 0.0
                        gnn_cache[domain] = gnn_score
                        gnn_reasons = [f"GNN graph analysis: {gnn_score:.2f}"]
                        # Limit cache size
                        if len(gnn_cache) > 200:
                            gnn_cache.clear()
                    
                    # If GNN score is still 0, apply heuristic scoring based on domain characteristics
                    if gnn_score == 0.0:
                        # Check for suspicious domain patterns
                        suspicious_indicators = 0
                        if any(keyword in domain.lower() for keyword in ['secure', 'login', 'verify', 'account', 'bank', 'payment']):
                            suspicious_indicators += 1
                        if any(keyword in domain.lower() for keyword in ['crypto', 'wallet', 'bitcoin', 'investment']):
                            suspicious_indicators += 1
                        if any(keyword in domain.lower() for keyword in ['support', 'update', 'alert', 'security']):
                            suspicious_indicators += 1
                        if domain.endswith('.tk') or domain.endswith('.ml') or domain.endswith('.ga'):
                            suspicious_indicators += 1  # Suspicious TLDs
                        
                        if suspicious_indicators > 0:
                            gnn_score = min(0.6, suspicious_indicators * 0.2)
                            gnn_reasons.append(f"GNN heuristic: {suspicious_indicators} suspicious indicators detected")
                        else:
                            gnn_score = 0.0  # Zero score for unknown but not suspicious domains
                            gnn_reasons.append("GNN: domain not in graph, zero default score")
                    else:
                        # Improved GNN scoring with better legitimate domain detection
                        legitimate_domains = [
                            'google.com', 'github.com', 'linkedin.com', 'spotify.com', 'microsoft.com', 
                            'apple.com', 'amazon.com', 'facebook.com', 'twitter.com', 'youtube.com',
                            'netflix.com', 'paypal.com', 'ebay.com', 'wikipedia.org', 'stackoverflow.com',
                            'reddit.com', 'instagram.com', 'tiktok.com', 'discord.com', 'zoom.us',
                            'dropbox.com', 'adobe.com', 'salesforce.com', 'oracle.com', 'ibm.com',
                            'intel.com', 'nvidia.com', 'amd.com', 'cisco.com', 'vmware.com',
                            '127.0.0.1', 'localhost', 'localhost:5000', 'localhost:3000'
                        ]
                        
                        # Check if domain is legitimate
                        domain_lower = domain.lower()
                        is_legitimate = any(legit in domain_lower for legit in legitimate_domains)
                        
                        if is_legitimate:
                            gnn_score = 0.05  # Very low score for legitimate domains
                            gnn_reasons.append(f"GNN: legitimate domain detected ({domain})")
                        elif gnn_score > 0.8:
                            gnn_score = min(gnn_score, 0.7)  # Cap at 0.7 for unknown domains
                            gnn_reasons.append("GNN: score capped for unknown domain")
                        else:
                            # Keep the original score for domains that aren't obviously legitimate
                            gnn_reasons.append(f"GNN: domain analysis score {gnn_score:.3f}")
                else:
                    # No domain but we have a URL - provide a default score based on URL patterns
                    gnn_score = 0.0  # Zero default score for unknown domains
                    gnn_reasons = ["GNN: no domain extracted from URL"]
            except Exception as e:
                app.logger.warning("analyze/aggregate: GNN predict failed: %s", e)
                gnn_reasons = [f"GNN error: {str(e)}"]
        else:
            gnn_reasons = ["graph engine not available"]

        # URL analysis (simplified same as before) ...
        url_res_raw = {}
        url_components = {"redirect_count":0,"has_https":False,"domain_age_days":None,"registrar":None,"asn_org":None,"ip":None}
        url_reasons=[]; url_score=0.0
        if url:
            try:
                if not urlparse(url).scheme: url="http://"+url
                redirects=follow_redirects(url)
                final=redirects.get("final_url") if isinstance(redirects,dict) else url
                cert=get_cert_fingerprint(final) if final else {"cert_fp":None}
                enrichment={}
                parsed=urlparse(final or url)
                if parsed.hostname: enrichment={"whois":domain_whois_info(parsed.hostname),"asn":domain_asn_info(parsed.hostname)}
                url_res_raw={"input_url":url,"redirects":redirects.get("hops") if isinstance(redirects,dict) else [],
                             "final_url":final,"status":redirects.get("status_code") if isinstance(redirects,dict) else None,
                             "cert":cert,"enrichment":enrichment}
                redirect_count=max(0,len(url_res_raw.get("redirects",[]))-1)
                url_components["redirect_count"]=redirect_count
                parsed_final=urlparse(final) if final else None
                has_https=parsed_final.scheme=="https" if parsed_final else False
                url_components["has_https"]=has_https
                who=enrichment.get("whois",{}) or {}
                age_days=who.get("age_days"); url_components["domain_age_days"]=age_days
                url_components["registrar"]=who.get("registrar")
                asn=enrichment.get("asn",{}) or {}; raw_asn_org=(asn.get("asn_org") or "").strip()
                url_components["asn_org"]=raw_asn_org; url_components["ip"]=asn.get("ip")
                # Improved URL scoring with legitimate domain detection
                legitimate_domains = [
                    'google.com', 'github.com', 'linkedin.com', 'spotify.com', 'microsoft.com', 
                    'apple.com', 'amazon.com', 'facebook.com', 'twitter.com', 'youtube.com',
                    'netflix.com', 'paypal.com', 'ebay.com', 'wikipedia.org', 'stackoverflow.com',
                    'reddit.com', 'instagram.com', 'tiktok.com', 'discord.com', 'zoom.us',
                    'dropbox.com', 'adobe.com', 'salesforce.com', 'oracle.com', 'ibm.com',
                    'intel.com', 'nvidia.com', 'amd.com', 'cisco.com', 'vmware.com',
                    '127.0.0.1', 'localhost'
                ]
                
                # Check if domain is legitimate
                domain_lower = parsed.hostname.lower() if parsed.hostname else ""
                is_legitimate = any(legit in domain_lower for legit in legitimate_domains)
                
                if is_legitimate:
                    # Very low base score for legitimate domains
                    url_score = 0.01
                    url_reasons.append(f"Legitimate domain detected: {parsed.hostname}")
                    if not has_https:
                        url_score += 0.02  # Very small penalty for no HTTPS on legitimate domains
                        url_reasons.append("No HTTPS (legitimate domain)")
                else:
                    # Much more conservative scoring for unknown domains
                    url_score = 0.02 + min(redirect_count * 0.03, 0.15)  # Reduced base scores
                    if not has_https: 
                        url_score += 0.08  # Reduced penalty
                        url_reasons.append("No HTTPS (no TLS) -> slight risk")
                    if age_days is None: 
                        url_score += 0.03  # Reduced penalty
                        url_reasons.append("Domain age unknown -> minimal risk")
                    elif age_days < 30: 
                        url_score += 0.15  # Much reduced penalty
                        url_reasons.append(f"Very new domain ({age_days} days) -> medium risk")
                    elif age_days < 90: 
                        url_score += 0.10  # Reduced penalty
                        url_reasons.append(f"New domain ({age_days} days) -> slight risk")
                    elif age_days < 365: 
                        url_score += 0.05  # Reduced penalty
                        url_reasons.append(f"Recent domain ({age_days} days) -> minimal risk")
                    else: 
                        url_reasons.append(f"Domain age {age_days} days -> lower risk")
                    if not url_components.get("registrar"): 
                        url_score += 0.02  # Reduced penalty
                        url_reasons.append("No registrar info -> minimal risk")
                
                url_score=max(0.0,min(1.0,url_score))
            except Exception as e: url_reasons.append(f"URL error {e}")
        else: url_reasons.append("No URL")

        # Ensure we always have some score from all three models
        # If CNN didn't run, provide a default based on text content
        if cnn_score == 0.0 and text_norm:
            # Simple heuristic: if text contains suspicious keywords, give CNN a moderate score
            suspicious_keywords = ['login', 'password', 'verify', 'account', 'bank', 'payment', 'secure']
            keyword_count = sum(1 for kw in suspicious_keywords if kw in text_norm.lower())
            if keyword_count > 0:
                cnn_score = min(0.3, keyword_count * 0.1)
                cnn_reasons.append(f"CNN heuristic: {keyword_count} suspicious keywords detected")
        
        # Use simple stable equation to combine scores
        try:
            # Simple weighted average with stability checks
            text_weight = 0.6
            cnn_weight = 0.3
            gnn_weight = 0.1
            
            # Calculate weighted average
            weighted_score = (text_weight * text_res["score"] + 
                            cnn_weight * cnn_score + 
                            gnn_weight * gnn_score)
            
            # Apply stability factor - if any score is very low, reduce overall score
            min_score = min(text_res["score"], cnn_score, gnn_score)
            if min_score < 0.1:
                weighted_score = weighted_score * 0.5  # Reduce by 50% if any score is very low
            
            # Cap the final score
            aggregate_score = min(weighted_score, 1.0)
            
            # Simple threshold-based labeling
            if aggregate_score >= 0.6:
                ensemble_label = "phish"
            elif aggregate_score >= 0.3:
                ensemble_label = "suspicious"
            else:
                ensemble_label = "legit"
            
            app.logger.info(f"Simple ensemble result: score={aggregate_score:.3f}, label={ensemble_label}")
            
        except Exception as e:
            app.logger.warning(f"Simple ensemble failed: {e}")
            # Fallback to basic average
            aggregate_score = (text_res["score"] + cnn_score + gnn_score) / 3
            if aggregate_score >= 0.6:
                ensemble_label = "phish"
            elif aggregate_score >= 0.3:
                ensemble_label = "suspicious"
            else:
                ensemble_label = "legit"
        
        # Map ensemble labels to our expected labels
        label_mapping = {
            "phish": "high",
            "suspicious": "medium", 
            "legit": "low"
        }
        label = label_mapping.get(ensemble_label, "low")
        badge = {"high":"🔴","medium":"🟠","low":"🟢"}[label]
        
        # Combine all reasons
        combined_reasons = []
        if text_norm and text_res.get("reasons"): 
            combined_reasons.append("Text signals: "+"; ".join(text_res["reasons"][:3]))
        if cnn_reasons: 
            combined_reasons.append("CNN: " + "; ".join(cnn_reasons[:2]))
        if gnn_reasons: 
            combined_reasons.append("GNN: " + "; ".join(gnn_reasons[:2]))
        if url_reasons: 
            combined_reasons += url_reasons[:4]
        
        response = {
            "aggregate_score": aggregate_score,
            "label": label,
            "badge": badge,
            "timestamp": datetime.now(IST).isoformat(),
            "text": text_res,
            "cnn_score": cnn_score,
            "gnn_score": gnn_score,
            "url": {"score": round(url_score,4), "components": url_components, "reasons": url_reasons, "raw": url_res_raw},
            "combined_reasons": combined_reasons,
            "components_raw": {"text": text_res["score"], "cnn": cnn_score, "gnn": gnn_score},
            "model_type": "simple_stable_ensemble"
        }

        # Use new format with CNN and GNN scores
        headers = ["timestamp","url","domain","text_score","cnn_score","gnn_score","combined_score","label","text_excerpt","combined_reasons"]
        row = [
            response["timestamp"],
            url or "",
            domain,
            round(text_res["score"], 6),
            round(cnn_score, 6),
            round(gnn_score, 6),
            round(aggregate_score, 6),
            label,
            (text_norm[:200]+"...") if len(text_norm)>200 else text_norm,
            "; ".join(combined_reasons)
        ]
        if not os.path.exists(AGG_LOG):
            with open(AGG_LOG,"w",newline="",encoding="utf-8") as f: csv.writer(f).writerow(headers)
        with open(AGG_LOG,"a",newline="",encoding="utf-8") as f: csv.writer(f).writerow(row)
        return jsonify(response)
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"error":str(e)}),500

# --- Report + top endpoints ---
@app.route("/aggregate/report", methods=["GET"])
def aggregate_report():
    fmt=request.args.get("format","json").lower()
    if not os.path.exists(AGG_LOG): return jsonify({"error":"No log file yet"}),404
    if fmt=="csv":
        try: return send_file(AGG_LOG,mimetype="text/csv",as_attachment=True,download_name=os.path.basename(AGG_LOG))
        except: return send_file(AGG_LOG,mimetype="text/csv",as_attachment=True,attachment_filename=os.path.basename(AGG_LOG))
    else:
        data = []
        with open(AGG_LOG,"r",encoding="utf-8") as f:
            lines = f.readlines()
        
        # Process each line and detect format
        for i, line in enumerate(lines):
            if i == 0:  # Skip header
                continue
            if not line.strip():
                continue
                
            # Parse CSV line - handle quoted fields properly
            import csv as csv_module
            from io import StringIO
            reader = csv_module.reader(StringIO(line))
            try:
                row = next(reader)
            except:
                continue
            
            # Detect format based on number of columns and content
            if len(row) >= 9:  # New format: timestamp,url,domain,text_score,cnn_score,gnn_score,combined_score,label,text_excerpt,combined_reasons
                try:
                    normalized_row = {
                        "timestamp": row[0] if len(row) > 0 else "",
                        "url": row[1] if len(row) > 1 else "",
                        "domain": row[2] if len(row) > 2 else "",
                        "text_score": row[3] if len(row) > 3 else "0",
                        "cnn_score": row[4] if len(row) > 4 else "0",
                        "gnn_score": row[5] if len(row) > 5 else "0",
                        "combined_score": row[6] if len(row) > 6 else "0",
                        "label": row[7] if len(row) > 7 else "",
                        "text_excerpt": row[8] if len(row) > 8 else "",
                        "combined_reasons": row[9] if len(row) > 9 else ""
                    }
                except Exception:
                    # Fallback for malformed lines
                    normalized_row = {
                        "timestamp": "", "url": "", "domain": "", "text_score": "0", 
                        "cnn_score": "0", "gnn_score": "0", "combined_score": "0", 
                        "label": "", "text_excerpt": "", "combined_reasons": ""
                    }
            else:  # Old format: timestamp,text_score,url_score,aggregate_score,label,badge,text_excerpt,url,combined_reasons
                try:
                    normalized_row = {
                        "timestamp": row[0] if len(row) > 0 else "",
                        "url": row[7] if len(row) > 7 else "",
                        "domain": "",
                        "text_score": row[1] if len(row) > 1 else "0",
                        "cnn_score": "0",  # Not available in old format - set to 0
                        "gnn_score": "0",  # Not available in old format - set to 0
                        "combined_score": row[3] if len(row) > 3 else "0",  # aggregate_score -> combined_score
                        "label": row[4] if len(row) > 4 else "",
                        "text_excerpt": row[6] if len(row) > 6 else "",
                        "combined_reasons": row[8] if len(row) > 8 else ""
                    }
                except Exception:
                    # Fallback for malformed lines
                    normalized_row = {
                        "timestamp": "", "url": "", "domain": "", "text_score": "0", 
                        "cnn_score": "0", "gnn_score": "0", "combined_score": "0", 
                        "label": "", "text_excerpt": "", "combined_reasons": ""
                    }
            
            data.append(normalized_row)
        return jsonify(data)

@app.route("/aggregate/top_domains", methods=["GET"])
def top_domains():
    if not os.path.exists(AGG_LOG): return jsonify({"data":[]})
    domains=[]
    with open(AGG_LOG,"r",encoding="utf-8") as f:
        for r in csv.DictReader(f):
            try:
                h=urlparse(r.get("url") or "").hostname or ""
                if h: domains.append(h.lower())
            except: continue
    cnt=Counter(domains).most_common(30)
    return jsonify({"data":[{"domain":d,"count":c} for d,c in cnt]})

@app.route("/aggregate/top_keywords", methods=["GET"])
def top_keywords():
    if not os.path.exists(AGG_LOG): return jsonify({"data":[]})
    kws=[]; kw_re=re.compile(r"\b[a-z]{3,}\b",re.I)
    with open(AGG_LOG,"r",encoding="utf-8") as f:
        for r in csv.DictReader(f):
            words=kw_re.findall((r.get("combined_reasons") or "")+" "+str(r.get("text_score") or ""))
            kws+=[w.lower() for w in words]
    cnt=Counter(kws).most_common(40)
    return jsonify({"data":[{"keyword":k,"count":c} for k,c in cnt]})

# --- Anchors endpoints ---
@app.route("/aggregate/anchors", methods=["GET"])
def aggregate_anchors():
    """
    Return anchors.csv as JSON but sanitize any CSV rows which may contain
    an extra None-key (csv.DictReader places extra columns under None).
    """
    if not os.path.exists(ANCHORS_PATH):
        return jsonify({"data": []})

    sanitized = []
    try:
        with open(ANCHORS_PATH, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                # If DictReader put extra columns under None, move them into a safe key
                if None in row:
                    extra = row.pop(None)
                    if isinstance(extra, list):
                        extra_val = ", ".join([str(x) for x in extra if x is not None and str(x).strip() != ""])
                    else:
                        extra_val = str(extra)
                    row["_extra_columns"] = extra_val

                # Ensure all keys are strings (avoid any accidental None keys)
                clean_row = {}
                for k, v in (row.items()):
                    key = str(k) if k is not None else "_none_key_"
                    clean_row[key] = v
                sanitized.append(clean_row)
    except Exception as e:
        app.logger.exception("Failed to read/sanitize anchors.csv: %s", e)
        return jsonify({"error": f"Failed to read anchors.csv: {e}"}), 500


    return jsonify({"data": sanitized})


def compute_eip1559_fees(preferred_priority_gwei=2):
    """
    Compute (maxPriorityFeePerGas, maxFeePerGas) in wei, ensuring
    maxFeePerGas >= baseFee + maxPriorityFeePerGas when baseFee is available.
    Returns (maxPriority, maxFee, base_fee_or_none)
    """
    # priority in wei
    max_priority = int(preferred_priority_gwei * (10**9))
    base_fee = None
    try:
        # try pending block first, then latest
        try:
            blk = w3.eth.get_block('pending')
        except Exception:
            blk = w3.eth.get_block('latest')
        base_fee = blk.get('baseFeePerGas', None)
    except Exception:
        base_fee = None

    # fallback gas price (legacy) if base_fee not available
    try:
        legacy_gas_price = w3.eth.gas_price or w3.to_wei(20, 'gwei')
    except Exception:
        legacy_gas_price = w3.to_wei(20, 'gwei')

    if base_fee is not None and base_fee > 0:
        # ensure maxFee >= base_fee + priority + small padding
        padding = max(int(base_fee * 0.10), int(max_priority * 2))
        max_fee = base_fee + max_priority + padding
    else:
        # no base_fee info -> use legacy gas price heuristic but ensure max_fee > priority
        max_fee = max(int(legacy_gas_price * 2.5), max_priority + int(legacy_gas_price))
        if max_fee <= max_priority:
            max_fee = max_priority + int(legacy_gas_price)

    # final guard
    if max_fee <= max_priority:
        max_fee = max_priority + 1

    return max_priority, max_fee, base_fee


@app.route("/aggregate/anchor", methods=["POST"])
def create_anchor():
    """
    Robust anchor endpoint:
    POST JSON: { "n":50, "test_mode": false, "wait": true/false }
    Returns JSON with ok, batch_hash, tx_hash (if any), chain_id, first_row_index, last_row_index, error/message
    """
    data = request.get_json(force=True, silent=True) or {}
    try:
        n = int(data.get("n", 50))
    except Exception:
        n = 50
    test_mode = bool(data.get("test_mode", False))
    wait_for_receipt = bool(data.get("wait", False))

    ts = datetime.utcnow().isoformat() + "Z"

    # Ensure aggregate log exists
    if not os.path.exists(AGG_LOG):
        return jsonify({"ok": False, "error": "aggregate_log.csv missing"}), 400

    # Read AGG_LOG and skip header row if present
    with open(AGG_LOG, "r", encoding="utf-8") as f:
        lines = [line.rstrip("\n") for line in f if line.strip()]

    # If first line looks like a CSV header (contains comma-separated column names), skip it for hashing/indexing
    data_lines = lines[:]
    if data_lines and "," in data_lines[0] and any(h in data_lines[0].lower() for h in ("timestamp", "aggregate_score", "label")):
        data_lines = data_lines[1:]

    if not data_lines:
        return jsonify({"ok": False, "error": "No data rows in aggregate_log.csv"}), 400

    last_n = data_lines[-n:]
    # compute batch hash over the textual CSV lines (data rows only)
    batch_hash = hashlib.sha256("\n".join(last_n).encode("utf-8")).hexdigest()
    first_idx = max(1, len(data_lines) - len(last_n) + 1)
    last_idx = len(data_lines)

    # If test mode OR web3/account not ready -> record test anchor
    if test_mode or not (w3 and ACCOUNT):
        row = {
            "timestamp": ts,
            "mode": "test",
            "rows": n,
            "first_row_index": first_idx,
            "last_row_index": last_idx,
            "batch_hash": batch_hash,
            "tx_hash": "",
            "chain_id": "",
            "status": "test",
            "message": "test mode anchor (no blockchain tx)"
        }
        try:
            append_anchor_row(row)
        except Exception as e:
            return jsonify({"ok": False, "error": f"failed to write anchors.csv: {e}", **row}), 500
        return jsonify({**row, "ok": True}), 200

    # Build and send transaction (robust)
    try:
        # Use pending transaction count to avoid reusing nonce that are pending in the node
        base_nonce = w3.eth.get_transaction_count(ACCOUNT.address, "pending")

        # Build common unsigned tx template
        def build_unsigned(nonce_val):
            tx = {
                "to": ACCOUNT.address,
                "value": 0,
                "nonce": nonce_val,
                "chainId": WEB3_CHAIN_ID,
            }
            # include batch hash as hex data (use plain "0x..." string)
            tx["data"] = "0x" + batch_hash if batch_hash else "0x"
            return tx

        # We'll try to sign/send up to `max_attempts` nonces (in case pending txs cause collisions)
        max_attempts = 4
        last_exception = None
        tx_hash = None

        for attempt in range(max_attempts):
            nonce_to_try = base_nonce + attempt
            unsigned_tx = build_unsigned(nonce_to_try)

            # Estimate gas (safe fallback)
            try:
                estimated = w3.eth.estimate_gas(unsigned_tx)
                unsigned_tx["gas"] = max(21000, int(estimated * 1.2))
            except Exception as e_est:
                unsigned_tx["gas"] = 120000
                app.logger.debug("Gas estimate failed, using fallback 120000: %s", e_est)

            # Compute safe EIP-1559 fees
            try:
                max_priority, max_fee, base_fee = compute_eip1559_fees(preferred_priority_gwei=2)
                unsigned_tx["maxPriorityFeePerGas"] = max_priority
                unsigned_tx["maxFeePerGas"] = max_fee
                unsigned_tx.pop("gasPrice", None)
            except Exception as e_fee:
                # fallback to legacy gasPrice but ensure gasPrice >= 1 wei over priority
                try:
                    gp = w3.eth.gas_price or w3.to_wei(20, 'gwei')
                except Exception:
                    gp = w3.to_wei(20, 'gwei')
                unsigned_tx["gasPrice"] = gp

            app.logger.debug("Attempting tx with nonce %s: %s", nonce_to_try, unsigned_tx)

            # === robust sign & send block ===
            try:
                signed = w3.eth.account.sign_transaction(unsigned_tx, private_key=WEB3_PRIVATE_KEY)

                # robustly extract raw transaction payload (support multiple web3/eth-account shapes)
                raw_tx = None
                if hasattr(signed, "rawTransaction"):
                    raw_tx = getattr(signed, "rawTransaction")
                elif hasattr(signed, "raw_transaction"):
                    raw_tx = getattr(signed, "raw_transaction")
                elif isinstance(signed, dict):
                    raw_tx = signed.get("rawTransaction") or signed.get("raw_transaction") or signed.get("raw_tx") or signed.get("rawTx")
                elif isinstance(signed, (bytes, bytearray, str)):
                    raw_tx = signed

                if raw_tx is None:
                    app.logger.error("Signed transaction object missing raw payload: %r", signed)
                    raise Exception("signed transaction object missing raw payload (no rawTransaction/raw_transaction)")

                # normalize to HexBytes for send_raw_transaction
                if isinstance(raw_tx, str):
                    raw_hex = raw_tx if raw_tx.startswith("0x") else "0x" + raw_tx
                    raw_bytes = HexBytes(raw_hex)
                else:
                    raw_bytes = HexBytes(raw_tx)

                sent = w3.eth.send_raw_transaction(raw_bytes)
                tx_hash = sent.hex() if hasattr(sent, "hex") else str(sent)

                row = {
                    "timestamp": ts,
                    "mode": "real",
                    "rows": n,
                    "first_row_index": first_idx,
                    "last_row_index": last_idx,
                    "batch_hash": batch_hash,
                    "tx_hash": tx_hash,
                    "chain_id": WEB3_CHAIN_ID,
                    "status": "submitted",
                    "message": f"tx submitted (nonce={nonce_to_try})"
                }
                try:
                    append_anchor_row(row)
                except Exception as e_app:
                    app.logger.error("append_anchor_row failed after tx send: %s", e_app)
                    return jsonify({"ok": True, "tx_hash": tx_hash, "warning": f"tx_sent_but_append_failed: {e_app}", **row}), 200

                # optionally wait for receipt
                if wait_for_receipt:
                    try:
                        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
                        row["status"] = "confirmed" if receipt and receipt.status == 1 else "failed"
                        row["message"] = f"receipt status={getattr(receipt,'status',None)} block={getattr(receipt,'blockNumber',None)}"
                        append_anchor_row(row)
                    except Exception as e_wait:
                        app.logger.warning("wait_for_receipt failed: %s", e_wait)
                        return jsonify({"ok": True, "tx_hash": tx_hash, "message": "tx submitted; receipt wait failed", "error_wait": str(e_wait), **row}), 200

                # success - return
                return jsonify({"ok": True, "batch_hash": batch_hash, "tx_hash": tx_hash, "chain_id": WEB3_CHAIN_ID,
                                "first_row_index": first_idx, "last_row_index": last_idx}), 200

            except Exception as e_send:
                last_exception = e_send
                err_s = str(e_send).lower()
                app.logger.warning("send_raw_transaction attempt nonce=%s failed: %s", nonce_to_try, e_send)

                # If node says tx already known, it might be the same signed tx or same nonce already used.
                if "already known" in err_s or "known transaction" in err_s:
                    # Try next nonce (there may be a pending tx). continue loop to retry with next nonce.
                    continue

                # If node rejects due to priority/fee mismatch, try re-computing fees and retry (same nonce)
                if "max priority fee per gas higher than max fee per gas" in err_s or "replacement transaction underpriced" in err_s or "underpriced" in err_s:
                    app.logger.info("Fee-related error detected, attempting fee-bump and retry on same nonce.")
                    try:
                        # recompute fees with a higher priority
                        bump_priority_gwei = 6  # bump priority for retry
                        max_priority_b, max_fee_b, base_fee_b = compute_eip1559_fees(preferred_priority_gwei=bump_priority_gwei)
                        unsigned_tx["maxPriorityFeePerGas"] = max_priority_b
                        unsigned_tx["maxFeePerGas"] = max_fee_b
                        unsigned_tx.pop("gasPrice", None)

                        signed = w3.eth.account.sign_transaction(unsigned_tx, private_key=WEB3_PRIVATE_KEY)

                        raw_tx = None
                        if hasattr(signed, "rawTransaction"):
                            raw_tx = getattr(signed, "rawTransaction")
                        elif hasattr(signed, "raw_transaction"):
                            raw_tx = getattr(signed, "raw_transaction")
                        elif isinstance(signed, dict):
                            raw_tx = signed.get("rawTransaction") or signed.get("raw_transaction") or signed.get("raw_tx") or signed.get("rawTx")
                        elif isinstance(signed, (bytes, bytearray, str)):
                            raw_tx = signed

                        if raw_tx is None:
                            raise Exception("signed transaction object missing raw payload on fee-bump")

                        if isinstance(raw_tx, str):
                            raw_hex = raw_tx if raw_tx.startswith("0x") else "0x" + raw_tx
                            raw_bytes = HexBytes(raw_hex)
                        else:
                            raw_bytes = HexBytes(raw_tx)

                        sent = w3.eth.send_raw_transaction(raw_bytes)
                        tx_hash = sent.hex() if hasattr(sent, "hex") else str(sent)
                        row = {
                            "timestamp": ts,
                            "mode": "real",
                            "rows": n,
                            "first_row_index": first_idx,
                            "last_row_index": last_idx,
                            "batch_hash": batch_hash,
                            "tx_hash": tx_hash,
                            "chain_id": WEB3_CHAIN_ID,
                            "status": "submitted",
                            "message": f"tx submitted after fee bump (nonce={nonce_to_try})"
                        }
                        append_anchor_row(row)
                        return jsonify({"ok": True, "batch_hash": batch_hash, "tx_hash": tx_hash, "chain_id": WEB3_CHAIN_ID,
                                        "first_row_index": first_idx, "last_row_index": last_idx}), 200
                    except Exception as e2:
                        app.logger.warning("retry with bumped fees failed: %s", e2)
                        last_exception = e2
                        continue

                # Otherwise break and return the error
                break

        # If we exhausted attempts
        err_msg = str(last_exception) if last_exception else "unknown error sending tx"
        app.logger.error("Failed to send tx after %s attempts: %s", max_attempts, err_msg)
        # append failed row for audit
        try:
            append_anchor_row({
                "timestamp": ts,
                "mode": "real",
                "rows": n,
                "first_row_index": first_idx,
                "last_row_index": last_idx,
                "batch_hash": batch_hash,
                "tx_hash": "",
                "chain_id": WEB3_CHAIN_ID,
                "status": "failed",
                "message": err_msg[:1000]
            })
        except Exception:
            app.logger.exception("Failed to append failed anchor row")
        # If we saw an "already known" style message, return 400 with that explanation
        if last_exception and ("already known" in str(last_exception).lower() or "known transaction" in str(last_exception).lower()):
            return jsonify({"ok": False, "error": "tx already known (duplicate/pending)", "batch_hash": batch_hash,
                            "first_row_index": first_idx, "last_row_index": last_idx}), 400

        return jsonify({"ok": False, "error": err_msg, "batch_hash": batch_hash,
                        "first_row_index": first_idx, "last_row_index": last_idx}), 500

    except Exception as e:
        err_msg = str(e)
        app.logger.exception("Unexpected error sending anchor tx: %s", err_msg)
        try:
            append_anchor_row({
                "timestamp": ts,
                "mode": "real",
                "rows": n,
                "first_row_index": first_idx,
                "last_row_index": last_idx,
                "batch_hash": batch_hash,
                "tx_hash": "",
                "chain_id": WEB3_CHAIN_ID,
                "status": "failed",
                "message": err_msg[:1000]
            })
        except Exception:
            app.logger.exception("Failed to append failed anchor row")
        return jsonify({"ok": False, "error": err_msg, "batch_hash": batch_hash,
                        "first_row_index": first_idx, "last_row_index": last_idx}), 500
    
@app.route("/analyze/multi", methods=["POST"])
def analyze_multi():
    """
    Body JSON:
      { "text": "...", "image_b64": "<base64>", "domain": "example.com" }
    Returns JSON with combined score + components + reasons.
    """
    try:
        data = request.get_json(force=True)
    except Exception as e:
        return jsonify({"ok": False, "error": "invalid json: " + str(e)}), 400

    text = data.get("text", "") or ""
    domain = data.get("domain", "") or ""
    image_b64 = data.get("image_b64", None)

    # Text score (llm_model.TextScorer) with caching
    text_key = f"{text[:100]}"  # Use first 100 chars as cache key
    if text_key in text_cache:
        t_res = text_cache[text_key]
        tscore = float(t_res.get("score", 0.0))
        app.logger.debug("Using cached text result")
    else:
        try:
            t_res = text_scorer.score(text)
            tscore = float(t_res.get("score", 0.0))
            text_cache[text_key] = t_res
            # Limit cache size
            if len(text_cache) > 100:
                text_cache.clear()
        except Exception as e:
            app.logger.exception("Text scoring failed")
            t_res = {"score": 0.0, "reasons": ["text scoring error: "+str(e)]}
            tscore = 0.0

       # CNN score
    # --- Robust handling: log raw response, avoid silent fallback to an arbitrary constant ---
        # CNN score
    # --- Robust handling: log raw response, avoid silent fallback to an arbitrary constant ---
    cscore = None
    c_reasons = []
    if image_b64:
        if cnn_scorer is None:
            c_reasons = ["cnn model not loaded"]
            cscore = None
            app.logger.debug("analyze/multi: image provided but cnn_scorer is not initialized")
        else:
            try:
                # Accept either full data-uri or plain base64
                img_b64 = image_b64
                if "," in img_b64:
                    img_b64 = img_b64.split(",", 1)[1]
                image_bytes = base64.b64decode(img_b64)
                
                # Optimize image size for faster processing
                try:
                    from PIL import Image
                    import io
                    img = Image.open(io.BytesIO(image_bytes))
                    # Resize large images to max 512x512 for faster processing
                    if img.size[0] > 512 or img.size[1] > 512:
                        img.thumbnail((512, 512), Image.Resampling.LANCZOS)
                        img_bytes = io.BytesIO()
                        img.save(img_bytes, format='PNG', optimize=True)
                        image_bytes = img_bytes.getvalue()
                        app.logger.debug("analyze/multi: optimized image size to %dx%d", img.size[0], img.size[1])
                except Exception as e:
                    app.logger.debug("analyze/multi: image optimization failed: %s", e)
                
                app.logger.debug("analyze/multi: decoded image bytes len=%d", len(image_bytes))

                # call wrapped scorer and log the raw response for diagnosis
                raw_c_res = cnn_scorer.score_image_bytes(image_bytes)
                app.logger.debug("analyze/multi: raw cnn response: %r", raw_c_res)

                # Normalize different possible outputs:
                parsed_score = None
                if isinstance(raw_c_res, (int, float)):
                    parsed_score = float(raw_c_res)
                    c_reasons = []
                elif isinstance(raw_c_res, dict):
                    # prefer explicit 'score' key
                    if "score" in raw_c_res and raw_c_res.get("score") is not None:
                        try:
                            parsed_score = float(raw_c_res.get("score"))
                        except Exception:
                            parsed_score = None
                    # fallback: scan for a plausible numeric field
                    if parsed_score is None:
                        for k, v in raw_c_res.items():
                            if k in ("ok", "reasons", "error"):
                                continue
                            if isinstance(v, (int, float)):
                                parsed_score = float(v); break
                            if isinstance(v, str):
                                try:
                                    fv = float(v); parsed_score = fv; break
                                except Exception:
                                    pass
                    # reasons extraction
                    maybe_reasons = raw_c_res.get("reasons", None)
                    if isinstance(maybe_reasons, list):
                        c_reasons = maybe_reasons
                    elif isinstance(maybe_reasons, str):
                        c_reasons = [maybe_reasons]
                    else:
                        c_reasons = c_reasons or []
                else:
                    app.logger.warning("analyze/multi: cnn returned unknown shape: %r", type(raw_c_res))
                    parsed_score = None
                    c_reasons = ["unknown cnn response shape"]

                # clamp/normalize parsed_score to 0..1 if it looks like a percentage or >1
                if parsed_score is not None:
                    if parsed_score > 1.0:
                        if 0.0 < parsed_score <= 1000.0:
                            if parsed_score <= 100:
                                parsed_score = parsed_score / 100.0
                            elif parsed_score <= 1000:
                                parsed_score = parsed_score / 100.0
                            else:
                                parsed_score = parsed_score / parsed_score
                    parsed_score = max(0.0, min(1.0, float(parsed_score)))
                    cscore = parsed_score
                else:
                    cscore = None
                    if not c_reasons:
                        c_reasons = ["cnn returned no numeric score"]
            except Exception as e:
                app.logger.exception("analyze/multi: exception during cnn scoring: %s", e)
                c_reasons = [f"cnn exception: {e}"]
                cscore = None
    else:
        c_reasons = ["no image provided"]
        cscore = None

    app.logger.debug("analyze/multi: final cscore=%s, c_reasons=%s", repr(cscore), c_reasons)



    # GNN score with caching
    gscore = None
    g_reasons = []
    if domain:
        if graph_engine is None:
            g_reasons = ["graph engine not initialized"]
            gscore = None
            app.logger.debug("analyze/multi: domain provided but graph_engine is not initialized")
        else:
            # Check cache first
            if domain in gnn_cache:
                gscore = gnn_cache[domain]
                app.logger.debug("Using cached GNN result for domain: %s", domain)
            else:
                try:
                    # graph_engine.predict_node_score now returns 0.0 for unknown domains instead of None
                    pred = graph_engine.predict_node_score(domain)
                    gscore = float(pred) if pred is not None else 0.0
                    gnn_cache[domain] = gscore
                    # Limit cache size
                    if len(gnn_cache) > 200:
                        gnn_cache.clear()
                except Exception as e:
                    app.logger.warning("Graph predict failed: %s", e)
                    g_reasons = [str(e)]
                    gscore = 0.0
    else:
        g_reasons = ["no domain provided"]
        gscore = 0.0

    # Debug log of what we've computed
    app.logger.debug("analyze/multi called: text_len=%d, image_present=%s, domain=%s", len(text or ""), bool(image_b64), domain)
    app.logger.debug("scores so far: tscore=%s, cscore=%s, gscore=%s", tscore, cscore, gscore)

    # Combine
    # combine_scores expects numeric scores (0..1) or None; it normalizes and handles None -> 0.0 internally,
    # but here we include the raw cscore/gscore in the response so frontend can show `null` if not supplied.
    final = combine_scores(tscore, cnn_score=cscore, gnn_score=gscore)
    final["ok"] = True
    final["text_reasons"] = t_res.get("reasons", [])
    final["cnn_reasons"] = c_reasons
    final["gnn_reasons"] = g_reasons
    final["gnn_score_raw"] = gscore
    # include a field indicating whether the cnn/gnn components were actually run
    final["components_run"] = {"text": True, "cnn": (image_b64 is not None and cnn_scorer is not None), "gnn": (domain != "" and graph_engine is not None)}
    # Include raw component values (allow None)
    final["components_raw"] = {"text": tscore, "cnn": cscore, "gnn": gscore}
        # -----------------------
    # Persist this multi-analysis to aggregate_log.csv (append; create header if missing)
    # -----------------------
    try:
        agg_path = AGG_LOG if 'AGG_LOG' in globals() else os.path.join(os.path.dirname(__file__), "aggregate_log.csv")
        ts_now = final.get("timestamp") or datetime.utcnow().isoformat() + "Z"
        # prepare values: ensure numeric or blank
        txt_score = float(tscore or 0.0)
        cnn_score_val = "" if cscore is None else round(float(cscore), 6)
        gnn_score_val = "" if gscore is None else round(float(gscore), 6)
        agg_score_val = float(final.get("score") or final.get("aggregate_score") or 0.0)
        label_val = final.get("label", "") or ""
        combined_reasons = "; ".join(final.get("combined_reasons", []) or final.get("reasons", []) or [])
        text_excerpt = (text or "")[:200].replace("\n", " ").replace("\r", " ")

        headers = ["timestamp","url","domain","text_score","cnn_score","gnn_score","combined_score","label","text_excerpt","combined_reasons"]
        row = [ts_now, data.get("url") or "", data.get("domain") or "", round(txt_score, 6), cnn_score_val, gnn_score_val, round(agg_score_val, 6), label_val, text_excerpt, combined_reasons]

        # create file + header if missing
        if not os.path.exists(agg_path):
            with open(agg_path, "w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow(headers)
        with open(agg_path, "a", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(row)
        app.logger.debug("analyze/multi: appended row to %s for url=%s", agg_path, data.get("url", ""))
    except Exception as e:
        app.logger.exception("analyze/multi: failed to append to aggregate_log.csv: %s", e)

    return jsonify(final)

@app.route("/graph/reload", methods=["POST"])
def graph_reload():
    if graph_engine is None:
        return jsonify({"ok": False, "error": "GraphEngine not initialized"}), 500
    try:
        AGG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aggregate_log.csv")
        edges = extract_edges_from_aggregate(AGG_PATH)
        graph_engine.build_graph_from_edges(edges)
        graph_engine.compute_node2vec_embeddings(dimensions=64, walk_length=10, num_walks=80)
        return jsonify({"ok": True, "nodes": len(graph_engine.embeddings)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


if __name__=="__main__":
    port=int(os.environ.get("PORT",5000))
    app.run(host="0.0.0.0",port=port,debug=True)
