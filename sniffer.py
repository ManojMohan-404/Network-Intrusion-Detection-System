from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, conf
import database
import time

SENSITIVE_PORTS = [22, 23, 3389, 445, 1433, 3306]
scan_tracker = {}
SCAN_THRESHOLD = 5
TIME_WINDOW = 10

def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        length = len(packet)
        proto = "IPv4"
        alert = "Normal"
        app_data = "-" # Variable for Layer 7 Application Data
        current_time = time.time()

        # 1. DEEP PACKET INSPECTION: DNS Queries
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            try:
                # Extract the domain name being requested
                query = packet[DNSQR].qname.decode('utf-8', errors='ignore')
                app_data = f"DNS: {query}"
                proto = "DNS"
            except:
                pass

        # 2. TRANSPORT LAYER: TCP
        elif TCP in packet:
            proto = "TCP"
            dport = packet[TCP].dport
            sport = packet[TCP].sport
            
            # DEEP PACKET INSPECTION: HTTP or Raw Text Payloads
            if packet.haslayer(Raw):
                try:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    # Look for common HTTP methods
                    if "HTTP" in payload or "GET " in payload or "POST " in payload:
                        proto = "HTTP"
                        # CAPTURE THE FULL FIRST LINE (No 60-character limit)
                        app_data = payload.split('\n')[0].strip()
                except:
                    pass

            # Port Scan Tracking
            if src_ip not in scan_tracker:
                scan_tracker[src_ip] = {'time': current_time, 'ports': set()}
            
            if current_time - scan_tracker[src_ip]['time'] > TIME_WINDOW:
                scan_tracker[src_ip] = {'time': current_time, 'ports': set()}
            
            scan_tracker[src_ip]['ports'].add(dport)
            
            if len(scan_tracker[src_ip]['ports']) >= SCAN_THRESHOLD:
                alert = "PORT SCAN"
            elif dport in SENSITIVE_PORTS or sport in SENSITIVE_PORTS:
                alert = "SENSITIVE PORT"

        # 3. TRANSPORT LAYER: UDP
        elif UDP in packet:
            proto = "UDP"
            
        
        # 4. NETWORK LAYER: ICMP
        elif ICMP in packet:
            proto = "ICMP"
            alert = "PING"
            # Attempt to grab the raw ping payload
            if packet.haslayer(Raw):
                try:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    app_data = f"ICMP Data: {payload}" # <--- LIMIT REMOVED
                except:
                    pass

        # Send to Database with the app_data column
        database.insert_log(src_ip, dst_ip, proto, length, alert, app_data)

def start_sniffer(interface=None):
    database.init_db()
    if not interface:
        interface = conf.iface
    print(f"[*] Starting DPI Capture Engine (Layer 4 & Layer 7)...")
    print(f"[*] Bound to interface: {interface.name if hasattr(interface, 'name') else interface}")
    sniff(iface=interface, prn=process_packet, store=False, promisc=True)