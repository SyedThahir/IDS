#!/usr/bin/env python3
import logging
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from ml_ids_core import MLNetworkClassifier
import time
import signal
import sys
from datetime import datetime
import os

# Configure logging
LOG_DIR = 'logs'
os.makedirs(LOG_DIR, exist_ok=True)

# Configure logging to both file and console
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, 'ids.log')),
        logging.StreamHandler()
    ]
)

class NetworkMonitor:
    def __init__(self):
        self.classifier = MLNetworkClassifier()
        self.running = True
        self.stats = {
            'total_packets': 0,
            'malicious_packets': 0,
            'start_time': time.time()
        }
        
        # Create alerts file
        self.alerts_file = os.path.join(LOG_DIR, f'alerts_{int(time.time())}.log')
        with open(self.alerts_file, 'w') as f:
            f.write("Timestamp,Protocol,Source,Destination,Flags,PayloadSize\n")
        
        # Create stats file
        self.stats_file = os.path.join(LOG_DIR, f'stats_{int(time.time())}.csv')
        with open(self.stats_file, 'w') as f:
            f.write("Timestamp,Runtime,TotalPackets,PacketsPerSec,MaliciousPackets,MaliciousPercent\n")
        
        # Register signal handlers
        signal.signal(signal.SIGINT, self.handle_interrupt)
        signal.signal(signal.SIGTERM, self.handle_interrupt)

    def packet_callback(self, packet):
        """Process each captured packet."""
        try:
            self.stats['total_packets'] += 1
            
            # Only analyze IP packets
            if IP not in packet:
                return
                
            # Analyze packet
            is_malicious = self.classifier.predict(packet)
            
            if is_malicious:
                self.stats['malicious_packets'] += 1
                self.log_malicious_packet(packet)
            
            # Print stats every 100 packets
            if self.stats['total_packets'] % 100 == 0:
                self.print_stats()
                
        except Exception as e:
            logging.error(f"Error processing packet: {str(e)}")

    def log_malicious_packet(self, packet):
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
            
            # Log to alerts CSV file
            with open(self.alerts_file, 'a') as f:
                f.write(f"{timestamp},{proto},{source},{dest},{flags},{payload_size}\n")
            
        except Exception as e:
            logging.error(f"Error logging malicious packet: {str(e)}")

    def print_stats(self):
        """Print and save monitoring statistics."""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            elapsed_time = time.time() - self.stats['start_time']
            packets_per_sec = self.stats['total_packets'] / elapsed_time
            malicious_percent = (self.stats['malicious_packets'] / self.stats['total_packets']) * 100 if self.stats['total_packets'] > 0 else 0
            
            # Print to console
            print("\n=== IDS Monitoring Statistics ===")
            print(f"Runtime: {elapsed_time:.1f} seconds")
            print(f"Total packets: {self.stats['total_packets']}")
            print(f"Packets per second: {packets_per_sec:.1f}")
            print(f"Malicious packets: {self.stats['malicious_packets']} ({malicious_percent:.1f}%)")
            print("===============================\n")
            
            # Save to stats CSV file
            with open(self.stats_file, 'a') as f:
                f.write(f"{timestamp},{elapsed_time:.1f},{self.stats['total_packets']},{packets_per_sec:.1f},{self.stats['malicious_packets']},{malicious_percent:.1f}\n")
            
        except Exception as e:
            logging.error(f"Error printing/saving stats: {str(e)}")

    def handle_interrupt(self, signum, frame):
        """Handle interrupt signals gracefully."""
        print("\nStopping IDS monitoring...")
        self.running = False
        self.print_stats()
        
        # Print summary of log locations
        print("\nLog files saved:")
        print(f"- IDS Log: {os.path.join(LOG_DIR, 'ids.log')}")
        print(f"- Alerts: {self.alerts_file}")
        print(f"- Statistics: {self.stats_file}\n")
        
        sys.exit(0)

    def start_monitoring(self, interface=None):
        """Start capturing and analyzing network traffic."""
        try:
            print(f"\nStarting IDS monitoring on interface: {interface or 'default'}")
            print("Press Ctrl+C to stop monitoring\n")
            
            # Start packet capture
            sniff(
                iface=interface,
                prn=self.packet_callback,
                store=0,  # Don't store packets in memory
                stop_filter=lambda _: not self.running  # Stop when self.running is False
            )
            
        except Exception as e:
            logging.error(f"Error starting monitoring: {str(e)}")
            self.running = False

def main():
    """Main function to start the IDS monitoring."""
    try:
        # Create and start monitor
        monitor = NetworkMonitor()
        
        # Use en0 interface directly
        monitor.start_monitoring('en0')
            
    except Exception as e:
        logging.error(f"Error in main: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 