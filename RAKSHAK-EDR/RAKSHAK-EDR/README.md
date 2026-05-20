# RAKSHAK-EDR 🛡️
### Endpoint Detection & Response – SOC Dashboard

---

## 🚀 Quick Start

### 1. Install Python
Download from https://python.org (Python 3.9+)

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the app
```bash
python app.py
```

### 4. Open browser
```
http://127.0.0.1:5000
```

### 5. Login
| Field    | Value      |
|----------|------------|
| Username | `admin`    |
| Password | `admin123` |

---

## 📁 Project Structure
```
RAKSHAK-EDR/
├── app.py              ← Main Flask server
├── detector.py         ← Packet sniffing module (Scapy)
├── database.py         ← DB utilities
├── requirements.txt    ← Python dependencies
├── logs/               ← CSV exports saved here
├── instance/           ← SQLite DB auto-created here
├── static/
│   ├── style.css       ← Cyberpunk UI styles
│   └── script.js       ← Live clock, alerts, terminal
└── templates/
    ├── index.html      ← Login page
    └── dashboard.html  ← SOC Dashboard
```

---

## ⚙️ Features
- 🔐 Login system with session management
- 📡 Live packet counter (simulated + optional Scapy)
- ⚠️ Auto threat detection with severity levels
- 🖥️ SOC-style dashboard with live terminal
- 📊 Threat logs table (ID, IP, Attack, Severity, Status)
- 🔔 Popup alerts when threats are high
- 📥 Export logs to CSV
- 🎨 Cyberpunk neon UI with animations

---

## 🪟 Windows – Real Packet Sniffing (Optional)
1. Install Npcap: https://npcap.com/
2. Run terminal as **Administrator**
3. `python app.py`

> Without Npcap, the dashboard still works using the built-in simulation engine.

---

## 🐧 Linux – Real Packet Sniffing (Optional)
```bash
sudo python app.py
```

---

## 🛠️ Tech Stack
| Layer     | Technology          |
|-----------|---------------------|
| Backend   | Python + Flask      |
| Database  | SQLite + SQLAlchemy |
| Sniffing  | Scapy               |
| Frontend  | HTML + CSS + JS     |
| UI Theme  | Cyberpunk / SOC     |

---

## 📌 Notes
- This is an **educational/demo** project
- Not intended for production use
- Threat data is **simulated** by default for demo purposes

---

*RAKSHAK-EDR — Built for learning cybersecurity & full-stack development*
