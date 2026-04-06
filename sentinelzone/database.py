import sqlite3
import os

DB_FILE = os.path.join(os.path.dirname(__file__), 'alerts.db')

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp  TEXT,
            alert_type TEXT,
            src_ip     TEXT,
            dst_ip     TEXT,
            protocol   TEXT,
            zone       TEXT,
            severity   TEXT,
            source     TEXT,
            message    TEXT
        )
    """)
    conn.commit()
    conn.close()

def insert_alert(alert):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        INSERT INTO alerts
        (timestamp, alert_type, src_ip, dst_ip, protocol, zone, severity, source, message)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alert.get('timestamp', ''),
        alert.get('alert_type', alert.get('type', '')),
        alert.get('src_ip', ''),
        alert.get('dst_ip', ''),
        alert.get('protocol', ''),
        alert.get('zone', ''),
        alert.get('severity', ''),
        alert.get('source', ''),
        alert.get('message', '')
    ))
    conn.commit()
    conn.close()

def get_all_alerts():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM alerts ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_recent_alerts(limit=50):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_latest_alert():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 1")
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None

def get_stats():
    conn = sqlite3.connect(DB_FILE)
    total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    sev_rows  = conn.execute(
        "SELECT severity,   COUNT(*) FROM alerts GROUP BY severity"
    ).fetchall()
    zone_rows = conn.execute(
        "SELECT zone,       COUNT(*) FROM alerts GROUP BY zone"
    ).fetchall()
    type_rows = conn.execute(
        "SELECT alert_type, COUNT(*) FROM alerts GROUP BY alert_type"
    ).fetchall()
    conn.close()
    return {
        'total':           total,
        'severity_counts': {r[0]: r[1] for r in sev_rows},
        'zone_counts':     {r[0]: r[1] for r in zone_rows},
        'type_counts':     {r[0]: r[1] for r in type_rows}
    }

def clear_alerts():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()