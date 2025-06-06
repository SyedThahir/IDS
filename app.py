from flask import Flask, render_template, request, redirect, url_for, jsonify
from ml_ids_core import MLNetworkClassifier
from scapy.all import *
from scapy.layers.inet import TCP, IP, UDP
import threading
import queue
import time
import logging
import os
from datetime import datetime

# Configure logging
LOG_DIR = 'logs'
os.makedirs(LOG_DIR, exist_ok=True)

app = Flask(__name__)

# Global variables
alerts = []
packet_queue = queue.Queue()
classifier = MLNetworkClassifier()
stats = {
    'total_packets': 0,
    'malicious_packets': 0,
    'start_time': time.time()
}

# Create log files
alerts_file = os.path.join(LOG_DIR, f'alerts_{int(time.time())}.log')
stats_file = os.path.join(LOG_DIR, f'stats_{int(time.time())}.csv')

# Initialize log files
with open(alerts_file, 'w') as f:
    f.write("Timestamp,Protocol,Source,Destination,Flags,PayloadSize\n")
with open(stats_file, 'w') as f:
    f.write("Timestamp,Runtime,TotalPackets,PacketsPerSec,MaliciousPackets,MaliciousPercent\n")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, 'ids.log')),
        logging.StreamHandler()
    ]
)

def log_malicious_packet(packet):
    """Log details of malicious packets."""
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if TCP in packet:
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = packet[TCP].flags
            source = f"{src_ip}:{sport}"
            dest = f"{dst_ip}:{dport}"
            log_msg = f"ALERT: Malicious {proto} packet detected - {timestamp}"
            log_msg += f"\n\tSource: {source} -> Destination: {dest}"
            log_msg += f"\n\tFlags: {flags}"
        elif UDP in packet:
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            source = f"{src_ip}:{sport}"
            dest = f"{dst_ip}:{dport}"
            flags = "N/A"
            log_msg = f"ALERT: Malicious {proto} packet detected - {timestamp}"
            log_msg += f"\n\tSource: {source} -> Destination: {dest}"
        else:
            proto = "IP"
            source = src_ip
            dest = dst_ip
            flags = "N/A"
            log_msg = f"ALERT: Malicious {proto} packet detected - {timestamp}"
            log_msg += f"\n\tSource: {source} -> Destination: {dest}"
        
        payload_size = len(packet[Raw].load) if Raw in packet else 0
        log_msg += f"\n\tPayload size: {payload_size} bytes"
        
        # Log to console and log file
        logging.warning(log_msg)
        alerts.append(log_msg)
        
        # Log to alerts CSV file
        with open(alerts_file, 'a') as f:
            f.write(f"{timestamp},{proto},{source},{dest},{flags},{payload_size}\n")
        
    except Exception as e:
        logging.error(f"Error logging malicious packet: {str(e)}")

def save_stats():
    """Save current monitoring statistics."""
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        elapsed_time = time.time() - stats['start_time']
        packets_per_sec = stats['total_packets'] / elapsed_time
        malicious_percent = (stats['malicious_packets'] / stats['total_packets']) * 100 if stats['total_packets'] > 0 else 0
        
        # Save to stats CSV file
        with open(stats_file, 'a') as f:
            f.write(f"{timestamp},{elapsed_time:.1f},{stats['total_packets']},{packets_per_sec:.1f},{stats['malicious_packets']},{malicious_percent:.1f}\n")
            
    except Exception as e:
        logging.error(f"Error saving stats: {str(e)}")

def process_packet(packet):
    """Process a single packet using ML models with enhanced logging."""
    if packet.haslayer(IP):
        stats['total_packets'] += 1
        is_malicious = classifier.predict(packet)
        
        if is_malicious:
            stats['malicious_packets'] += 1
            log_malicious_packet(packet)
            
        # Save stats every 100 packets
        if stats['total_packets'] % 100 == 0:
            save_stats()

def packet_sniffer():
    """Background thread for continuous packet sniffing."""
    while True:
        try:
            sniff(iface='en0', prn=lambda x: packet_queue.put(x), store=0, count=1)
        except Exception as e:
            logging.error(f"Sniffing error: {str(e)}")
            time.sleep(1)

def packet_processor():
    """Background thread for processing captured packets."""
    while True:
        try:
            packet = packet_queue.get()
            process_packet(packet)
        except Exception as e:
            logging.error(f"Processing error: {str(e)}")
            time.sleep(1)

@app.route('/')
def dashboard():
    """Main dashboard showing alerts and statistics."""
    # Get filter parameters
    ip_filter = request.args.get('ip', '')
    protocol_filter = request.args.get('protocol', '')
    severity_filter = request.args.get('severity', '')
    port_filter = request.args.get('port', '')
    
    # Apply filters
    filtered_alerts = alerts
    
    if ip_filter:
        filtered_alerts = [a for a in filtered_alerts if ip_filter in a]
    if protocol_filter:
        filtered_alerts = [a for a in filtered_alerts if protocol_filter in a]
    if port_filter:
        filtered_alerts = [a for a in filtered_alerts if f":{port_filter}" in a]
    if severity_filter:
        # Add severity filtering based on payload size and flags
        if severity_filter == 'high':
            filtered_alerts = [a for a in filtered_alerts if 'SYN' in a or 'RST' in a]
        elif severity_filter == 'medium':
            filtered_alerts = [a for a in filtered_alerts if 'FIN' in a or 'PSH' in a]
    
    return render_template('dashboard.html', 
                         alerts=filtered_alerts[-50:],
                         request=request)

@app.route('/stats')
def get_stats():
    """Get real-time statistics about the IDS."""
    elapsed_time = time.time() - stats['start_time']
    packets_per_sec = stats['total_packets'] / elapsed_time if elapsed_time > 0 else 0
    malicious_percent = (stats['malicious_packets'] / stats['total_packets'] * 100) if stats['total_packets'] > 0 else 0
    
    # Calculate protocol distribution from recent alerts
    recent_alerts = alerts[-100:]  # Look at last 100 alerts
    tcp_count = sum(1 for alert in recent_alerts if 'TCP' in alert)
    udp_count = sum(1 for alert in recent_alerts if 'UDP' in alert)
    other_count = len(recent_alerts) - tcp_count - udp_count
    
    return jsonify({
        'total_packets': stats['total_packets'],
        'malicious_packets': stats['malicious_packets'],
        'packets_per_second': round(packets_per_sec, 1),
        'malicious_percent': round(malicious_percent, 1),
        'runtime': round(elapsed_time, 1),
        'queue_size': packet_queue.qsize(),
        'models_loaded': classifier.rf_model is not None and classifier.svm_model is not None,
        'protocol_distribution': {
            'tcp': tcp_count,
            'udp': udp_count,
            'other': other_count
        }
    })

if __name__ == '__main__':
    # Start background threads
    sniffer_thread = threading.Thread(target=packet_sniffer, daemon=True)
    processor_thread = threading.Thread(target=packet_processor, daemon=True)
    
    sniffer_thread.start()
    processor_thread.start()
    
    print("""
    ###########################################
    # ML-Based Network Intrusion Detection    #
    # - Random Forest & SVM Classifiers       #
    # - Real-time Traffic Analysis            #
    # - Web Dashboard Interface               #
    # - Comprehensive Logging                 #
    ###########################################
    """)
    
    app.run(debug=True, port=5051, use_reloader=False)
