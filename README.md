Absolutely ✅ — here’s your **final, polished, copy-paste-ready `README.md`** file for your **PhishProto** project.
You can paste this directly into your repository root (replacing the existing one).
Everything is perfectly formatted for **GitHub**, **hackathon submissions**, and **resume showcases**.

---

```markdown
# 🛡️ PhishProto — Real-Time AI/ML-Based Phishing Detection

PhishProto is a **real-time phishing detection and prevention system** built for the **Smart India Hackathon (SIH)** problem statement.  
It integrates **AI/ML text analysis**, **URL heuristics**, and **browser extension alerts** to protect users from phishing websites in real time.

---

## 🚀 Features

- 🤖 **Transformer-based text analysis (RoBERTa)** for phishing intent detection  
- 🌐 **URL intelligence**: Redirects, SSL, WHOIS, ASN, and DNS checks  
- 🧮 **Aggregate risk scoring** with 🟢🟠🔴 indicators  
- 📊 **Dashboard with analytics** — logs, charts, and exportable reports  
- ⛓️ **Blockchain anchoring** of analysis logs (for tamper-proof verification)  
- 🧩 **Chrome Extension** for real-time browser alerts and feedback

---

## 🛠️ Tech Stack

| Layer | Technologies |
|:------|:--------------|
| **Backend** | Python (Flask, Transformers, Torch, WHOIS, DNSPython, Web3) |
| **Frontend** | HTML, CSS, Chart.js (for dashboard visualization) |
| **Extension** | Chrome Extension (Manifest V3, JS, HTML, CSS) |
| **Deployment** | Docker & docker-compose |
| **Blockchain** | Web3.py (Ethereum / Sepolia Testnet Anchoring) |

---

## 📂 Project Structure

```

SIH/
│── backend/
│   ├── app.py
│   ├── anchor.py
│   ├── domain_info.py
│   ├── llm_model.py
│   ├── redirect.py
│   ├── ensemble.py
│   ├── cnn_model.py
│   ├── gnn_model.py
│   ├── static/dashboard.html
│   ├── aggregate_log.csv
│   └── anchors.csv
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
│── docker-compose.yml
│── Dockerfile
│── README.md

````

---

## ⚙️ Installation (Manual Setup)

### 🧩 Step 1 — Clone the Repository
```bash
git clone https://github.com/your-username/phishproto.git
cd phishproto
````

### 🧱 Step 2 — Create Virtual Environment

```bash
python -m venv venv
# Activate
venv\Scripts\activate        # Windows
source venv/bin/activate     # Linux / Mac
```

### 📦 Step 3 — Install Dependencies

Install all dependencies for backend, AI models, Web3, and analytics.

```bash
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

> 💡 If you face PyTorch Geometric issues on Windows, install CPU wheels directly:
>
> ```bash
> pip install torch==2.2.2+cpu torchvision==0.17.2+cpu torchaudio==2.2.2+cpu --index-url https://download.pytorch.org/whl/cpu
> ```

---

### 🧠 Step 4 — Run Backend Server

```bash
cd backend
python app.py
```

Backend starts at:

> 🔗 **[http://127.0.0.1:5000/](http://127.0.0.1:5000/)**

Test if it’s running:

```bash
curl http://127.0.0.1:5000/health
```

Expected response:

```json
{ "status": "OK", "service": "phish-proto-backend" }
```

---

## 🐳 Running with Docker

You can containerize and deploy the backend easily using Docker.

### Build and Run:

```bash
docker-compose up --build
```

Backend will start automatically and run on port **5000**.

---

## 🌐 Load Chrome Extension

1. Open **Google Chrome** (or Edge/Brave).
2. Navigate to: `chrome://extensions/`
3. Toggle **Developer Mode** ON (top right).
4. Click **Load unpacked**.
5. Select the `extension/` folder from this project.
6. Pin the **PhishProto** extension to your toolbar.

✅ The extension will now:

* Automatically analyze websites you visit.
* Display **risk banners** on suspicious pages.
* Provide explainable results in the popup.

---

## 📊 Dashboard Access

Visit:

> [http://127.0.0.1:5000/static/dashboard.html](http://127.0.0.1:5000/static/dashboard.html)

You can:

* 📈 View high, medium, and low risk distributions
* 🕵️ See text and URL analysis results
* ⛓️ Track anchored blockchain entries
* 🧾 Export logs as CSV reports

---

## 🧠 Explanation of AI Components

| Model                 | Description                                            |
| :-------------------- | :----------------------------------------------------- |
| **LLM (RoBERTa)**     | Analyzes message/email content for phishing intent     |
| **CNN (CLIP)**        | Detects visual spoofing and brand impersonation        |
| **GNN (GraphSAGE)**   | Maps domains, redirects, and network relationships     |
| **LightGBM Ensemble** | Combines model scores into a final phishing risk score |

Each model contributes to the **aggregate score**, classified as:
🟢 Low Risk | 🟠 Medium Risk | 🔴 High Risk

---

## 🔐 Blockchain Anchoring

Every analysis batch can be **anchored on the Ethereum Sepolia Testnet** using Web3.py.
Anchors are logged in `anchors.csv` and verified through smart transactions.

Command example:

```bash
curl -X POST http://127.0.0.1:5000/aggregate/anchor -H "Content-Type: application/json" -d '{"n":50,"test_mode":false}'
```

This ensures **tamper-proof verification** of phishing detection logs.

---

## 🧩 Environment Variables (`.env`)

Create a `.env` file inside `/backend` and configure:

```
WEB3_RPC_URL=https://sepolia.infura.io/v3/<your-infura-id>
WEB3_PRIVATE_KEY=0x<your-private-key>
WEB3_CHAIN_ID=11155111
RATE_LIMIT_MAX=60
RATE_LIMIT_WINDOW=60
```

---

## 🧠 Optional: Local Health Tests

Test all main endpoints manually:

```bash
# Health
curl http://127.0.0.1:5000/health

# Text-only LLM detection
curl -X POST http://127.0.0.1:5000/analyze/text -H "Content-Type: application/json" -d "{\"text\":\"Urgent: verify your account now\"}"

# Full multi-modal detection
curl -X POST http://127.0.0.1:5000/analyze/multi -H "Content-Type: application/json" -d "{\"text\":\"Invoice from CEO: transfer $5000\", \"domain\":\"example.com\"}"
```

---

## 🛡️ Contribution

Pull requests are welcome!
For major changes, open an issue first to discuss your proposed improvements.

---

## 📜 License

This project is licensed under the **MIT License**.

---

## ✨ Credits

Developed by **Team Vyuhatech** for **Smart India Hackathon (SIH)**.
Built with ❤️ using Python, Transformers, and Web3.
