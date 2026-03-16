# 🛡️ Hybrid Network Intrusion Detection System (NIDS)

A production-grade Network Intrusion Detection System combining **XGBoost ML** with **Large Language Models (LLMs)** for adaptive, explainable threat detection — with immutable **blockchain threat logging** and a real-time cybersecurity dashboard.

---

## 🚀 Features

| Feature | Details |
|---|---|
| **98.5% Detection Accuracy** | XGBoost primary model (F1-Score) |
| **Hybrid ML + LLM Detection** | LLM engaged for low-confidence predictions & zero-day threats |
| **Blockchain Threat Logging** | Immutable SHA-256 chained blocks for every detected attack |
| **Real-Time Packet Capture** | Scapy-based live traffic analysis via Npcap |
| **Explainable AI** | LLM generates natural-language reasoning for each detection |
| **Three-Page Dashboard** | Real-time monitoring, prediction interface, blockchain explorer |
| **REST API** | Full Flask API for integration with other tools |

---

## 📋 Prerequisites

| Requirement | Version |
|---|---|
| Python | 3.10+ |
| [Npcap](https://npcap.com/) | Latest (Windows only, required for live capture) |
| LLM API Key | GitHub PAT, OpenAI, or Anthropic |

> ⚠️ **Live packet capture requires running as Administrator** on Windows.

---

## ⚡ Quick Start

### 1. Clone & Set Up Environment

```powershell
git clone https://github.com/YOUR_USERNAME/Network.git
cd Network

python -m venv venv
.\venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

### 2. Configure Environment Variables

```powershell
copy .env.example .env
# Edit .env and add your API key
notepad .env
```

### 3. Prepare Data & Train Models

Download the [CICIDS 2017 dataset](https://www.unb.ca/cic/datasets/ids-2017.html) and place it as `cicids.csv` in the project root, then:

```powershell
# Preprocess dataset (creates data/ artifacts)
python src/preprocessing.py

# Train and evaluate ML models (creates models/ artifacts)
python src/model_training.py
```

### 4. Start the Server

```powershell
# Run as Administrator for live packet capture
python src/app.py
```

The server starts at **http://localhost:5000** and automatically opens the dashboard.

---

## 🖥️ Dashboard Pages

| Page | URL | Description |
|---|---|---|
| **Real-Time Monitor** | `/ui/realtime` | Live packet feed, traffic chart, start/stop capture |
| **Prediction Interface** | `/ui/index` | Manual feature input, model comparison |
| **Blockchain Explorer** | `/ui/blockchain` | Visualize threat logs, verify chain integrity |

---

## 📁 Project Structure

```
Network/
├── src/
│   ├── app.py                # Flask API server (main entry point)
│   ├── preprocessing.py      # Dataset cleaning, feature selection, normalization
│   ├── model_training.py     # XGBoost / SVM / LogReg training & evaluation
│   ├── feature_extractor.py  # 82-feature extraction from live Scapy packets
│   ├── network_capture.py    # Real-time Scapy packet sniffer
│   ├── hybrid_detector.py    # ML + LLM hybrid decision logic
│   ├── llm_detector.py       # LLM provider abstraction (GitHub/OpenAI/Anthropic)
│   ├── blockchain_logger.py  # SHA-256 blockchain for immutable threat logs
│   └── traffic_converter.py  # Converts packet features → LLM-readable description
├── ui/
│   ├── realtime.html         # Real-time monitoring dashboard
│   ├── index.html            # Prediction & model stats interface
│   └── blockchain.html       # Blockchain explorer
├── models/
│   └── model_results.json    # Evaluation metrics (model binaries excluded)
├── data/
│   └── feature_columns.npy   # Feature names used by the trained model
├── simulate_attacks.py       # Attack simulation script for testing
├── requirements.txt
├── .env.example              # Template for environment variables
└── README.md
```

---

## 🔌 API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | System health check |
| `GET` | `/api/stats` | Dataset & model statistics |
| `GET` | `/api/models/info` | Loaded model details & performance |
| `POST` | `/api/predict` | Single traffic prediction |
| `POST` | `/api/predict/batch` | Batch traffic prediction |
| `POST` | `/api/predict/hybrid` | ML + LLM hybrid prediction |
| `GET` | `/api/llm/status` | LLM availability & provider |
| `GET` | `/api/blockchain` | Full blockchain log |
| `GET` | `/api/blockchain/verify` | Verify chain integrity |
| `POST` | `/api/capture/start` | Start live packet capture |
| `POST` | `/api/capture/stop` | Stop live packet capture |
| `GET` | `/api/capture/status` | Capture stats & recent packets |
| `GET` | `/api/capture/export` | Export packet history as JSON |

---

## 🤖 LLM Providers

The hybrid detector supports three LLM providers. Set `LLM_PROVIDER` in your `.env`:

| Provider | `.env` value | API Key Variable | Notes |
|---|---|---|---|
| **GitHub Models** (Llama 3.3 70B) | `github` | `GITHUB_API_KEY` | Free with GitHub account |
| **OpenAI** (GPT-4o-mini) | `openai` | `OPENAI_API_KEY` | Paid |
| **Anthropic** (Claude 3 Haiku) | `anthropic` | `ANTHROPIC_API_KEY` | Paid |

---

## 📊 Model Performance

| Model | Accuracy | F1-Score | ROC-AUC |
|---|---|---|---|
| **XGBoost** ⭐ | 98.5% | 98.5% | 99.7% |
| SVM | 96.2% | 96.2% | 98.1% |
| Logistic Regression | 89.2% | 89.2% | 94.3% |

---

## 🧪 Testing

```powershell
# Test packet capture visibility (run as Administrator)
python test_packet_visibility.py

# Simulate various attack patterns
python simulate_attacks.py
```

---

## ⚙️ How It Works

```
Live Traffic → Scapy Capture → 82 Feature Extraction → XGBoost Prediction
                                                              │
                                              Confidence ≥ 0.992?
                                              ├── YES → Return Result
                                              └── NO  → LLM Analysis → Return Result
                                                              │
                                              Attack Detected → Blockchain Logger
                                                              │
                                              SHA-256 Block Mined & Chained
```

---

## 🔒 Security Notes

- **Never commit `.env`** — it contains your API keys
- The `.gitignore` excludes `.env` automatically
- Rotate your GitHub PAT if it was ever exposed in a commit
- Run with Administrator privileges only when needed for capture

---

## 📦 Dependencies

```
scikit-learn>=1.7.2   XGBoost    Flask    Flask-CORS
Scapy                 openai     joblib   python-dotenv
numpy==1.24.3         pandas     requests matplotlib
```

---

## ✅ Status

- ✅ Data preprocessing pipeline  
- ✅ Multi-model training & comparison (XGBoost / SVM / LogReg)  
- ✅ REST API backend (Flask)  
- ✅ Real-time packet capture (Scapy + Npcap)  
- ✅ Hybrid ML + LLM detection  
- ✅ Blockchain threat logging  
- ✅ Three-page interactive dashboard  
- ✅ Attack simulation & testing scripts  

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
