#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.inet import TCP, IP
from scapy.layers.dns import DNSQR
from collections import defaultdict
import datetime
import os
import sys
import platform

# ===== Configuration =====
SCAN_THRESHOLD = 10       # Alert if >10 ports probed
SYN_FLOOD_THRESHOLD = 50  # Alert if >50 SYN packets
SSH_BRUTE_THRESHOLD = 5   # Alert after 5 failed SSH attempts
DNS_TUNNEL_LENGTH = 50    # Alert if DNS query >50 chars

# ===== Global Variables =====
port_scan_count = defaultdict(int)
syn_count = defaultdict(int)
ssh_attempts = defaultdict(int)
alerts = []  # For Flask dashboard

# ===== Helper Functions =====
def log_alert(alert_msg):
    """Log alerts to file and Flask dashboard."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("ids_log.txt", "a") as log_file:
        log_file.write(f"[{timestamp}] ALERT: {alert_msg}\n")
    alerts.append(f"[{timestamp}] {alert_msg}")  # For Flask
    print(f"[!] {alert_msg}")

def block_ip(malicious_ip):
    """Block IP based on the OS (Mac, Linux, Windows)"""
    os_type = platform.system()

    try:
        if os_type == "Darwin":  # macOS
            if f"block drop from {malicious_ip}" in os.popen("sudo pfctl -sr 2>/dev/null").read():
                return
            os.system(f'echo "block drop from {malicious_ip} to any" | sudo pfctl -ef - 2>/dev/null')
            log_alert(f"Blocked IP on macOS: {malicious_ip}")

        elif os_type == "Linux":
            if malicious_ip in os.popen("sudo iptables -L INPUT -v -n").read():
                return
            os.system(f"sudo iptables -A INPUT -s {malicious_ip} -j DROP")
            log_alert(f"Blocked IP on Linux: {malicious_ip}")

        elif os_type == "Windows":
            cmd = f'netsh advfirewall firewall add rule name="Block {malicious_ip}" dir=in action=block remoteip={malicious_ip}'
            os.system(cmd)
            log_alert(f"Blocked IP on Windows: {malicious_ip}")

        else:
            log_alert(f"Unsupported OS for blocking IP: {os_type}")

    except Exception as e:
        log_alert(f"Failed to block {malicious_ip} on {os_type}: {str(e)}")

# ===== Detection Functions =====
def detect_port_scan(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        port_scan_count[src_ip] += 1
        
        if port_scan_count[src_ip] == SCAN_THRESHOLD:  # Only alert once per scan
            alert_msg = f"Port Scan detected from {src_ip}"
            log_alert(alert_msg)
            block_ip(src_ip)

def detect_syn_flood(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        src_ip = packet[IP].src
        syn_count[src_ip] += 1
        
        if syn_count[src_ip] == SYN_FLOOD_THRESHOLD:  # Only alert once per flood
            alert_msg = f"SYN Flood detected from {src_ip}"
            log_alert(alert_msg)
            block_ip(src_ip)

def detect_ssh_bruteforce(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 22:  # SSH port
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            if "Failed password" in payload:
                src_ip = packet[IP].src
                ssh_attempts[src_ip] += 1
                
                if ssh_attempts[src_ip] == SSH_BRUTE_THRESHOLD:  # Only alert once
                    alert_msg = f"SSH Brute Force attempt from {src_ip}"
                    log_alert(alert_msg)
                    block_ip(src_ip)

def detect_dns_tunneling(packet):
    if packet.haslayer(DNSQR):
        query = packet[DNSQR].qname.decode('utf-8', errors='ignore')
        if len(query) > DNS_TUNNEL_LENGTH:
            src_ip = packet[IP].src
            alert_msg = f"DNS Tunneling attempt from {src_ip}: {query[:50]}..."
            log_alert(alert_msg)

# ===== Main Sniffer =====
def packet_callback(packet):
    try:
        if packet.haslayer(IP):
            detect_port_scan(packet)
            detect_syn_flood(packet)
            detect_ssh_bruteforce(packet)
            detect_dns_tunneling(packet)
    except Exception as e:
        log_alert(f"Error processing packet: {str(e)}")

def initialize_firewall():
    """Initialize MacOS packet filter"""
    try:
        # Enable pf if not already enabled
        if "Status: Enabled" not in os.popen("sudo pfctl -si 2>/dev/null").read():
            os.system("sudo pfctl -e 2>/dev/null")
        
        # Flush existing rules
        os.system("sudo pfctl -F all 2>/dev/null")
        log_alert("Firewall initialized")
    except Exception as e:
        log_alert(f"Firewall initialization failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    print("""
    #######################################
    # Advanced IDS for MacOS              #
    # Detects:                            #
    # - Port Scans                        #
    # - SYN Floods                        #
    # - SSH Brute Force                   #
    # - DNS Tunneling                     #
    #######################################
    """)
    
    initialize_firewall()
    print("[*] Starting packet capture...")
    print("[*] Alerts will be saved to ids_log.txt")
    print("[*] Press Ctrl+C to stop\n")
    
    try:
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\n[!] Stopping IDS...")
        # Optional: Flush firewall rules when exiting
        # os.system("sudo pfctl -F all 2>/dev/null")
    except Exception as e:
        log_alert(f"Fatal error: {str(e)}")