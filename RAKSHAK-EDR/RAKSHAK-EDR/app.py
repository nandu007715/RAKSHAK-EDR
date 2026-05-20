from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from functools import wraps
import csv
import io
import random
import threading
import time

from auth import verify_password, seed_default_users
from roles import has_permission, get_role_label
from host_monitor import get_host_info
from detector import start_sniffing, get_status as detector_status

app = Flask(__name__)
app.secret_key = "rakshak_enterprise_secret_2026"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///rakshak.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# =========================
# Models
# =========================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(30), nullable=False)
    active = db.Column(db.Boolean, default=True)


class ThreatLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    attack = db.Column(db.String(120), nullable=False)
    ip = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(30), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    time = db.Column(db.String(30), nullable=False)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    action = db.Column(db.String(255))
    time = db.Column(db.String(30))


with app.app_context():
    db.create_all()
    seed_default_users(User, db)


# =========================
# Data
# =========================
ATTACKS = [
    "ARP Spoofing",
    "MITM Attack",
    "DDoS Flood",
    "Port Scan",
    "SQL Injection",
    "Brute Force",
    "DNS Poisoning",
    "SYN Flood",
    "Zero-Day Exploit",
    "Ransomware Probe",
    "ICMP Flood"
]

SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
STATUSES = ["Blocked", "Investigating", "Detected"]

packet_count = 0
threat_count = 0
last_detector_len = 0


# =========================
# Helpers
# =========================
def audit(username, action):
    log = AuditLog(
        username=username,
        action=action,
        time=datetime.now().strftime("%H:%M:%S")
    )
    db.session.add(log)
    db.session.commit()


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return wrapper


def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            role = session.get("role")

            if not has_permission(role, permission):
                return jsonify({"error": "permission denied"}), 403

            return f(*args, **kwargs)
        return wrapper
    return decorator


def ai_assessment(logs):
    if not logs:
        return {
            "risk": "LOW",
            "message": "No active threats detected.",
            "recommendation": "Continue monitoring."
        }

    latest = logs[0]
    attack = latest.attack

    if "Port" in attack:
        return {
            "risk": "HIGH",
            "message": "Reconnaissance pattern detected.",
            "recommendation": "Block scanning source and inspect exposed ports."
        }

    if "ARP" in attack:
        return {
            "risk": "HIGH",
            "message": "ARP spoof signature observed.",
            "recommendation": "Validate gateway MAC bindings."
        }

    if "Flood" in attack:
        return {
            "risk": "CRITICAL",
            "message": "Traffic flood pattern detected.",
            "recommendation": "Apply rate limiting and isolate source."
        }

    if "Brute" in attack:
        return {
            "risk": "CRITICAL",
            "message": "Credential attack pattern detected.",
            "recommendation": "Lock accounts and enable MFA."
        }

    return {
        "risk": "MODERATE",
        "message": "Suspicious activity under review.",
        "recommendation": "Continue active inspection."
    }


# =========================
# Hybrid Engine
# =========================
def simulate():
    global packet_count, threat_count, last_detector_len

    while True:
        time.sleep(random.uniform(5, 10))

        packet_count += random.randint(100, 500)

        det = detector_status()
        alerts = det.get("latest_alerts", [])

        if len(alerts) > last_detector_len:
            new_alerts = alerts[last_detector_len:]

            with app.app_context():
                for a in new_alerts:
                    exists = ThreatLog.query.filter_by(
                        attack=a["attack"],
                        ip=a["ip"],
                        time=a["time"]
                    ).first()

                    if not exists:
                        log = ThreatLog(
                            attack=a["attack"],
                            ip=a["ip"],
                            status=a["status"],
                            severity=a["severity"],
                            time=a["time"]
                        )
                        db.session.add(log)
                        db.session.commit()
                        threat_count += 1

            last_detector_len = len(alerts)

        elif random.random() < 0.55:
            with app.app_context():
                log = ThreatLog(
                    attack=random.choice(ATTACKS),
                    ip=f"192.168.{random.randint(0,255)}.{random.randint(1,254)}",
                    status=random.choice(STATUSES),
                    severity=random.choice(SEVERITIES),
                    time=datetime.now().strftime("%H:%M:%S")
                )

                db.session.add(log)
                db.session.commit()
                threat_count += 1


threading.Thread(target=simulate, daemon=True).start()


# =========================
# Routes
# =========================
@app.route("/")
def index():
    if "user" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/auth", methods=["POST"])
def auth():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    user = User.query.filter_by(username=username).first()

    if user and user.active and verify_password(password, user.password):
        session["user"] = user.username
        session["role"] = user.role

        audit(user.username, "LOGIN")
        return redirect(url_for("dashboard"))

    return render_template(
        "index.html",
        error="Invalid credentials. Access denied."
    )


@app.route("/dashboard")
@login_required
def dashboard():
    logs = ThreatLog.query.order_by(ThreatLog.id.desc()).limit(50).all()

    return render_template(
        "dashboard.html",
        logs=logs,
        packet_count=packet_count,
        threat_count=threat_count,
        last_scan=datetime.now().strftime("%H:%M:%S"),
        username=session["user"],
        role=session["role"],
        role_label=get_role_label(session["role"]),
        host=get_host_info(),
        ai=ai_assessment(logs),
        can_inject=has_permission(session["role"], "inject_threat"),
        can_clear=has_permission(session["role"], "clear_logs"),
        can_export=has_permission(session["role"], "export_csv")
    )


@app.route("/api/status")
@login_required
def api_status():
    logs = ThreatLog.query.order_by(ThreatLog.id.desc()).limit(30).all()
    ai = ai_assessment(logs)

    return jsonify({
        "packet_count": packet_count,
        "threat_count": threat_count,
        "last_scan": datetime.now().strftime("%H:%M:%S"),
        "host": get_host_info(),
        "ai": ai,
        "logs": [
            {
                "id": l.id,
                "attack": l.attack,
                "ip": l.ip,
                "status": l.status,
                "severity": l.severity,
                "time": l.time
            }
            for l in logs
        ]
    })


@app.route("/add-threat", methods=["POST"])
@login_required
@permission_required("inject_threat")
def add_threat():
    global threat_count

    data = request.get_json() or {}

    log = ThreatLog(
        attack=data.get("attack", "Manual Entry"),
        ip=data.get("ip", "0.0.0.0"),
        status=data.get("status", "Detected"),
        severity=data.get("severity", "MEDIUM"),
        time=datetime.now().strftime("%H:%M:%S")
    )

    db.session.add(log)
    db.session.commit()

    threat_count += 1
    audit(session["user"], f"Injected threat: {log.attack}")

    return jsonify({"success": True})


@app.route("/clear-logs", methods=["POST"])
@login_required
@permission_required("clear_logs")
def clear_logs():
    ThreatLog.query.delete()
    db.session.commit()

    audit(session["user"], "Cleared logs")

    return jsonify({"success": True})


@app.route("/export-csv")
@login_required
def export_csv():
    if not has_permission(session["role"], "export_csv"):
        return redirect(url_for("dashboard"))

    logs = ThreatLog.query.order_by(ThreatLog.id.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["ID", "Attack Type", "IP Address", "Status", "Severity", "Time"])

    for l in logs:
        writer.writerow([l.id, l.attack, l.ip, l.status, l.severity, l.time])

    output.seek(0)

    audit(session["user"], "Exported CSV")

    return Response(
        output,
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=rakshak_threats.csv"
        }
    )


@app.route("/logout")
def logout():
    user = session.get("user")

    if user:
        audit(user, "LOGOUT")

    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    print("\n" + "=" * 55)
    print("      RAKSHAK-EDR :: ENTERPRISE BUILD")
    print("=" * 55)
    print(" admin   / admin123")
    print(" analyst / analyst123")
    print(" cisco   / cisco123")
    print(" viewer  / viewer123")
    print("=" * 55 + "\n")

    start_sniffing()
    app.run(debug=True, port=5000)