"""
database.py – Standalone DB utilities for RAKSHAK-EDR.
"""
import sqlite3, os, csv
from collections import Counter

DB_PATH = os.path.join(os.path.dirname(__file__), 'instance', 'rakshak.db')

def _connect():
    return sqlite3.connect(DB_PATH)

def fetch_all_logs():
    try:
        conn = _connect()
        cur  = conn.cursor()
        cur.execute("SELECT id,attack,ip,status,severity,time FROM threat_log ORDER BY id DESC")
        rows = cur.fetchall()
        conn.close()
        keys = ('id','attack','ip','status','severity','time')
        return [dict(zip(keys, r)) for r in rows]
    except Exception as e:
        print(f"[DB] Error: {e}")
        return []

def export_to_csv(filepath='logs/threat_logs.csv'):
    logs = fetch_all_logs()
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['id','attack','ip','status','severity','time'])
        w.writeheader()
        w.writerows(logs)
    print(f"[DB] Exported {len(logs)} records → {filepath}")
    return filepath

def get_summary():
    logs = fetch_all_logs()
    if not logs:
        return {}
    return {
        'total':       len(logs),
        'by_severity': dict(Counter(l['severity'] for l in logs)),
        'by_attack':   dict(Counter(l['attack']   for l in logs)),
        'blocked':     sum(1 for l in logs if l['status'] == 'Blocked'),
    }

if __name__ == '__main__':
    print(get_summary())
    export_to_csv()
