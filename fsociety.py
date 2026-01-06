from flask import Flask, render_template, jsonify, request
import subprocess, os, csv, time

app = Flask(__name__)

# ใช้ตัวแปรตามไฟล์ fsociety.py
INTERFACE = "wlan0"
TEMP_FILE = "/tmp/fsociety_scan"
LOG_FILE = "/tmp/web_status.log"

def write_log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")

@app.route('/')
def index():
    return render_template('index.html')

# ดักทุกชื่อที่ Browser อาจจะเรียกหา เพื่อกัน 404
@app.route('/api/data')
@app.route('/api/status')
@app.route('/api/get_networks')
def get_all_data():
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            logs = f.readlines()[-5:] # เอา 5 บรรทัดล่าสุดมาทำ Log

    networks = []
    csv_path = f"{TEMP_FILE}-01.csv"
    if os.path.exists(csv_path):
        try:
            with open(csv_path, 'r', encoding='latin-1') as f:
                reader = csv.reader(f)
                for row in list(reader):
                    if len(row) > 13 and ":" in row[0]:
                        networks.append({"ssid": row[13].strip(), "bssid": row[0], "ch": row[3]})
        except: pass
    
    # เช็คสถานะการ์ดไวไฟ
    res = subprocess.run(f"ip link show {INTERFACE}", shell=True, capture_output=True, text=True)
    is_up = "UP" in res.stdout
    
    return jsonify({"logs": logs, "networks": networks, "is_up": is_up})

@app.route('/api/scan', methods=['POST'])
@app.route('/api/start_scan', methods=['POST'])
def start_scan():
    write_log("Web-Command: Starting Scan...")
    subprocess.run(f"sudo rm -f {TEMP_FILE}*", shell=True)
    # รัน airodump-ng ตาม fsociety
    subprocess.Popen(f"sudo airodump-ng {INTERFACE} --write {TEMP_FILE} --output-format csv", shell=True)
    return jsonify({"status": "ok"})

if __name__ == '__main__':
    if os.path.exists(LOG_FILE): os.remove(LOG_FILE)
    write_log("Server Started")
    app.run(host='0.0.0.0', port=5000)
