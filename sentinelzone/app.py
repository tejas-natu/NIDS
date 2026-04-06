from flask import Flask, request, jsonify, session, redirect, render_template
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import threading
import time
from database import (init_db, insert_alert, get_all_alerts,
                       get_recent_alerts, get_latest_alert, get_stats)

app = Flask(__name__)
app.secret_key = 'sentinelzone-secret-key'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins='*')

# ─── Auth ────────────────────────────────────────────────────────
USERNAME  = 'admin'
PASSWORD  = 'admin'
START_TIME = time.time()

# ─── Auth routes ─────────────────────────────────────────────────

@app.route('/')
def index():
    if 'logged_in' in session:
        return redirect('/dashboard')
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html', error=None)

    username = request.form.get('username')
    password = request.form.get('password')

    if username == 'admin' and password == 'admin':
        session['logged_in'] = True
        session['username'] = username
        return jsonify({'status': 'success'})
    else:
        return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 400

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/dashboard')
def dashboard():
    if 'logged_in' not in session:
        return redirect('/login')
    return render_template('dashboard.html')

# ─── Alert ingestion ─────────────────────────────────────────────

@app.route('/alert', methods=['POST'])
def receive_alert():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON received'}), 400
    insert_alert(data)
    print(f"[ALERT] [{data.get('zone','?')}] [{data.get('severity','?')}] {data.get('alert_type','?')} from {data.get('src_ip','?')}")
    socketio.emit('new_alert', data)
    return jsonify({'status': 'ok'}), 200

# ─── REST API ────────────────────────────────────────────────────

@app.route('/api/data')
def api_data():
    alerts = get_all_alerts()
    total  = len(alerts)

    attack_types = {}
    zone_distribution = {
        'Admin': 0, 'Staff':   0, 'Student': 0,
        'IoT':   0, 'Server':  0, 'External': 0
    }
    severity_counts = {
        'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0
    }

    for a in alerts:
        t = a.get('alert_type', a.get('type', ''))
        z = a.get('zone', '')
        s = a.get('severity', '')
        if t:
            attack_types[t] = attack_types.get(t, 0) + 1
        if z in zone_distribution:
            zone_distribution[z] += 1
        if s in severity_counts:
            severity_counts[s] += 1

    traffic_timeseries = [max(0, total // 10 + i) for i in range(10)]
    return jsonify({
        'total_attacks':     total,
        'total_traffic':     total * 2,
        'attack_types':      attack_types,
        'zone_distribution': zone_distribution,
        'severity_counts':   severity_counts,
        'traffic_timeseries': traffic_timeseries
    })

@app.route('/api/alerts')
def api_alerts():
    return jsonify(get_recent_alerts(50))

@app.route('/api/latest')
def api_latest():
    alert = get_latest_alert()
    if alert:
        return jsonify({'severity': alert.get('severity', 'NONE'),
                        'zone':     alert.get('zone', 'NONE')})
    return jsonify({'severity': 'NONE', 'zone': 'NONE'})

@app.route('/api/stats')
def api_stats():
    return jsonify(get_stats())

# ─── Background thread — pushes stats every 1 second ─────────────

def background_thread():
    while True:
        try:
            with app.app_context():
                stats  = get_stats()
                uptime = int(time.time() - START_TIME)
                socketio.emit('stats_update', stats)
                socketio.emit('system_status', {
                    'uptime_seconds': uptime,
                    'uptime_display': f"{uptime // 3600:02d}:{(uptime % 3600) // 60:02d}:{uptime % 60:02d}",
                    'status': 'running'
                })
        except Exception as e:
            print(f"[FLASK] Background error: {e}")
        time.sleep(1)

# ─── SocketIO events ─────────────────────────────────────────────

@socketio.on('connect')
def on_connect():
    print("[FLASK] Client connected")
    emit('stats_update', get_stats())

@socketio.on('disconnect')
def on_disconnect():
    print("[FLASK] Client disconnected")

# ─── Main ────────────────────────────────────────────────────────

if __name__ == '__main__':
    init_db()
    print("=" * 45)
    print("  SentinelZone Flask Server")
    print("  URL:   http://0.0.0.0:5000")
    print(f"  Login: {USERNAME} / {PASSWORD}")
    print("=" * 45)

    t = threading.Thread(target=background_thread, daemon=True)
    t.start()
    print("[FLASK] Background thread started")

    socketio.run(app, host='0.0.0.0', port=5000, debug=False)