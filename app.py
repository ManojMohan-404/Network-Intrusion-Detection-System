from flask import Flask, render_template, jsonify
import threading
import database
import sniffer
import requests

app = Flask(__name__)

# --- CONFIGURATION ---
# Change this to your exact network adapter name if you only want to listen to one.
# For example: "Wi-Fi", "eth0", "wlan0". Leave as None to listen to all.
NETWORK_INTERFACE = None 
# ---------------------

# Start the sniffer engine in a background thread
sniffer_thread = threading.Thread(target=sniffer.start_sniffer, args=(NETWORK_INTERFACE,), daemon=True)
sniffer_thread.start()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/logs')
def logs():
    # Fetch the latest 100 packets from the database to feed the dashboard
    data = database.get_all_logs()
    return jsonify(data)

@app.route('/ip/<ip_address>')
def ip_intel(ip_address):
    # 1. External OSINT (GeoIP & ISP Data)
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=3).json()
        country = response.get('country', 'Local / Unknown')
        isp = response.get('isp', 'Unknown ISP')
    except:
        country, isp = "Offline/Unknown", "Unknown ISP"

    # 2. Internal Network Context (Query our SQLite DB)
    logs = database.get_ip_context(ip_address)
    
    # Calculate statistics for this specific IP
    total_packets = len(logs)
    alerts_triggered = sum(1 for log in logs if log[6] != 'Normal')
    
    # 3. Dynamic Threat Scoring
    if ip_address.startswith(("192.168.", "10.", "127.", "172.")):
        base_score = 0
        status = "Internal Asset"
    else:
        # Increase the threat score if this IP triggered alerts on our network
        base_score = min(15 + (alerts_triggered * 10), 100) 
        status = "External Host"

    # Determine risk level for UI styling
    risk_level = "Low"
    if base_score > 40: risk_level = "Medium"
    if base_score > 75: risk_level = "High"

    # THIS is the crucial part that passes 'alerts' and 'total_packets' to the HTML
    return render_template('ip.html', 
                           ip=ip_address, 
                           score=base_score, 
                           country=country, 
                           isp=isp,
                           status=status,
                           risk_level=risk_level,
                           alerts=alerts_triggered,
                           total_packets=total_packets,
                           logs=logs)

if __name__ == '__main__':
    # Initialize the database on startup
    database.init_db()
    print("[*] SOC Dashboard starting up...")
    print("[*] Access it at: http://127.0.0.1:5000")
    
    # Run the web server
    app.run(host='0.0.0.0', port=5000, debug=False)