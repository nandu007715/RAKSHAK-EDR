# RAKSHAK – Enterprise Endpoint Detection & Response (EDR)

## Overview

RAKSHAK – Enterprise Endpoint Detection & Response (EDR) is a cybersecurity monitoring platform designed to simulate a real-world Security Operations Center (SOC) environment. The system continuously monitors network activity, detects suspicious behavior, logs incidents, and provides a professional dashboard for threat analysis and response.

The project combines intrusion detection concepts with modern web development to create an interactive security monitoring platform suitable for academic demonstration, cybersecurity learning, and lightweight enterprise simulation.

---

## Key Features

### 1) Multi-Role Login System (RBAC)

The platform implements Role-Based Access Control (RBAC) with separate user privileges:

**SOC Admin**

* Full dashboard access
* Inject threat events
* Clear threat logs
* Export CSV reports
* Monitor incidents
* Manage system activity

**Analyst**

* Investigate threats
* Review logs
* Export reports
* Monitor dashboard

**Cisco Engineer**

* Monitor network activity
* Review packet telemetry
* Export reports

**Viewer**

* Read-only dashboard access

---

### 2) Real-Time Threat Monitoring

The system continuously generates and monitors:

* ARP Spoofing attempts
* Port Scan detection
* ICMP Flood activity
* Brute Force patterns
* DDoS traffic simulation
* DNS anomalies
* Suspicious reconnaissance attempts

---

### 3) Incident Response Workflow

Security incidents can be managed through:

* Investigate
* Block IP
* Quarantine
* Resolve
* Ignore

This simulates real SOC analyst workflows.

---

### 4) Host Telemetry Panel

Displays live host information:

* Hostname
* IP Address
* MAC Address
* Operating System
* CPU Usage
* RAM Usage
* Disk Usage
* Uptime

---

### 5) AI Threat Assessment

Built-in threat intelligence engine analyzes:

* Attack behavior
* Risk level
* Severity posture
* Recommended response actions

---

### 6) Threat Log Database

All incidents are logged with:

* Threat ID
* Timestamp
* Attack Type
* Source IP
* Severity
* Status

---

### 7) CSV Export

Threat logs can be exported for:

* Incident reports
* Security auditing
* Documentation
* Offline analysis

---

## Technology Stack

### Backend

* Python
* Flask
* SQLite
* Scapy
* psutil

### Frontend

* HTML5
* CSS3
* JavaScript

### Security Concepts Used

* Intrusion Detection System (IDS)
* Endpoint Detection & Response (EDR)
* Security Operations Center (SOC)
* Role-Based Access Control (RBAC)
* Threat Logging
* Incident Response Workflow

---

## Default Login Credentials

| Role           | Username | Password   |
| -------------- | -------- | ---------- |
| SOC Admin      | admin    | admin123   |
| Analyst        | analyst  | analyst123 |
| Cisco Engineer | cisco    | cisco123   |
| Viewer         | viewer   | viewer123  |

---

## Project Structure

```text
RAKSHAK-Enterprise-EDR/
│
├── app.py
├── auth.py
├── roles.py
├── host_monitor.py
├── detector.py
├── database.py
├── requirements.txt
├── README.md
│
├── templates/
│   ├── index.html
│   └── dashboard.html
│
├── static/
│   ├── style.css
│   └── script.js
│
├── logs/
│   └── README.txt
│
└── instance/
    └── rakshak.db
```

---

## Installation

Install dependencies:

```bash
pip install -r requirements.txt
```

Run application:

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

---

## Learning Outcomes

This project demonstrates practical understanding of:

* Cybersecurity monitoring
* Intrusion detection concepts
* Network telemetry
* Incident handling
* Backend web development
* Database integration
* Security dashboard design

---

## Future Scope

* SIEM integration
* Threat intelligence feeds
* Geo-location attack map
* Real firewall automation
* Email alerting
* Machine learning anomaly detection

---

## Author

Developed as a B.Tech Cyber Security Project for academic and practical learning purposes.

---

## License

Educational / Academic Use
