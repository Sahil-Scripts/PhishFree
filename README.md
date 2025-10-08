
# 🛡️ PhishFree — Real-Time AI Phishing Detection & Prevention

PhishFree is an **AI-powered real-time phishing-detection framework** that integrates text, image, and domain-graph intelligence with explainable browser-extension alerts.
It combines **RoBERTa (LLM)** + **CLIP (CNN)** + **GraphSAGE (GNN)** + **LightGBM ensemble**, anchored to the blockchain for verification.

---

## 🚀 Key Features

* 🤖 **LLM (RoBERTa)** — Detects phishing language and social-engineering patterns
* 🖼️ **CNN (CLIP + MLP Head)** — Identifies visual spoofing / fake brand UIs
* 🌐 **GNN (GraphSAGE)** — Flags malicious domain relationships (redirects, ASNs, WHOIS)
* 🧮 **LightGBM Fusion** — Combines multi-modal scores into one risk index
* ⛓️ **Web3 Anchoring** — Immutable log of analyses on Ethereum Sepolia
* 🧩 **Chrome Extension (MV3)** — Live site-risk banners & explainable breakdowns

---

## 🧠 Tech Stack

| Layer              | Technologies                                           |
| :----------------- | :----------------------------------------------------- |
| **Language / Env** | Python 3.10.0                                          |
| **AI / ML**        | PyTorch, Transformers, Sentence-Transformers, LightGBM |
| **Graph Engine**   | PyTorch Geometric ( GraphSAGE fallback )               |
| **Backend API**    | Flask + Flask-CORS                                     |
| **Blockchain**     | Web3.py (Ethereum Sepolia)                             |
| **Frontend / UI**  | HTML + JS + Tailwind (CSS)                             |
| **Extension**      | Manifest V3 Chrome Extension                           |

---

## 📂 Project Structure

```
PhishFree/
│── backend/
│   ├── app.py
│   ├── llm_model.py
│   ├── cnn_model.py
│   ├── gnn_model.py
│   ├── ensemble.py
│   ├── domain_info.py
│   ├── anchor.py
│   └── ...
│
│── extension/
│   ├── manifest.json
│   ├── background.js
│   ├── content_script.js
│   ├── popup.html
│   ├── popup.js
│   └── popup.css
│
│── requirements.txt
│── .gitignore
│── README.md
```

---

## ⚙️ Setup Guide (Manual)

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/Sahil-Scripts/PhishFree.git
cd PhishFree
```

### 2️⃣ Create & Activate Virtual Environment (Python 3.10)

```bash
python -m venv venv
venv\Scripts\activate          # Windows
# or
source venv/bin/activate       # Linux / macOS
```

### 3️⃣ Install Dependencies

```bash
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt --extra-index-url https://download.pytorch.org/whl/cpu
```

> 💡 For GPU with CUDA 12.1:
>
> ```bash
> pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121
> pip install -r requirements.txt
> ```

---

## 🧠 Run Backend Server

```bash
cd backend
python app.py
```

Backend starts at **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

Test:

```bash
curl http://127.0.0.1:5000/health
```

Expected → `{"status":"OK","service":"phishfree-backend"}`

---

## 🧩 Environment Variables (`backend/.env`)

```
WEB3_RPC_URL=https://sepolia.infura.io/v3/<your-infura-id>
WEB3_PRIVATE_KEY=0x<your-private-key>
WEB3_CHAIN_ID=11155111
RATE_LIMIT_MAX=60
RATE_LIMIT_WINDOW=60
```

---

## 🧱 Run with Docker

```bash
docker build -t phishfree-backend .
docker run -p 5000:5000 phishfree-backend
```

or

```bash
docker-compose up --build
```

---

## 🌐 Load Chrome Extension

1. Open **Chrome** → `chrome://extensions/`
2. Enable **Developer Mode**
3. Click **Load unpacked**
4. Select the `extension/` folder
5. Pin 🛡️ **PhishFree** to toolbar

✅ Now the extension will automatically:

* Analyze every page visit
* Show 🟢🟠🔴 risk banner
* Provide “Run CNN” / “Run GNN” buttons for manual analysis
* Display explainable model scores

---

## 📊 Dashboard Access

Visit → **[http://127.0.0.1:5000/static/dashboard.html](http://127.0.0.1:5000/static/dashboard.html)**

You can:

* View risk distribution charts
* Inspect text / visual / graph scores
* Review anchored logs
* Export CSV reports

---

## 🧠 AI Model Breakdown

| Model               | Purpose                                       |
| :------------------ | :-------------------------------------------- |
| **RoBERTa (LLM)**   | Detects phishing intent in page/email text    |
| **CLIP (CNN Head)** | Flags visual spoofing and brand impersonation |
| **GraphSAGE (GNN)** | Finds domain/network relationships            |
| **LightGBM Fusion** | Combines all model scores into final risk     |

🟢 Low Risk | 🟠 Medium Risk | 🔴 High Risk

---

## ⛓️ Blockchain Anchoring

Every aggregate analysis can be anchored on Sepolia Testnet.

Example:

```bash
curl -X POST http://127.0.0.1:5000/aggregate/anchor \
-H "Content-Type: application/json" \
-d '{"n":25,"test_mode":false}'
```

Logs saved to `backend/anchors.csv`.

---

## 🧾 Testing Endpoints

```bash
# Health
curl http://127.0.0.1:5000/health

# Text-only
curl -X POST http://127.0.0.1:5000/analyze/text \
     -H "Content-Type: application/json" \
     -d "{\"text\":\"Urgent: verify your account now\"}"

# Multi-modal (text + cnn)
curl -X POST http://127.0.0.1:5000/analyze/multi \
     -H "Content-Type: application/json" \
     -d "{\"text\":\"Update your password\",\"run_models\":[\"cnn\"]}"
```

---

## 🧪 Verify Installation

```bash
python backend/test_cnn_local.py backend/demo_payloads/example1.png
```

Expected output ≈ `score ≈ 0.5–0.8` ✅

---

## 🧑‍💻 Contributing

1. Fork the repo
2. Create a branch (`git checkout -b feature-xyz`)
3. Commit changes
4. Push and open a PR

---

## 📜 License

MIT License © 2025 Sahil Pradhan

---

## ❤️ Credits

Built by **Sahil Pradhan (@Sahil-Scripts)** under Team Vyuhatech for Smart India Hackathon 2025.
Powered by Python 3.10, Transformers, CLIP, LightGBM, and Web3.

---
