#!/usr/bin/env python3
import random
import logging
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
import numpy as np
from ml_ids_core import MLNetworkClassifier
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def create_packet(src_ip, dst_ip, sport, dport, proto="TCP", flags=None, payload=None):
    """Helper function to create valid packets."""
    try:
        # Create IP packet
        ip = IP(src=src_ip, dst=dst_ip)
        
        # Create transport layer packet
        if proto == "TCP":
            if not flags:
                flags = "S"  # Default to SYN
            transport = TCP(sport=sport, dport=dport, flags=flags)
        else:  # UDP
            transport = UDP(sport=sport, dport=dport)
        
        # Combine layers
        pkt = ip/transport
        
        # Add payload if specified
        if payload:
            pkt = pkt/Raw(load=payload)
        
        # Verify packet is valid
        if not pkt.haslayer(IP) or (proto == "TCP" and not pkt.haslayer(TCP)) or (proto == "UDP" and not pkt.haslayer(UDP)):
            logging.error("Invalid packet created")
            return None
            
        return pkt
    except Exception as e:
        logging.error(f"Error creating packet: {str(e)}")
        return None

def generate_normal_traffic():
    """Generate normal network traffic patterns."""
    logging.info("Generating normal traffic patterns...")
    packets = []
    
    # HTTP/HTTPS traffic with realistic patterns
    for i in range(1000):
        try:
            # Simulate normal web browsing
            if random.random() < 0.7:  # 70% chance of being HTTPS
                dport = 443
                sport = random.randint(49152, 65535)  # Ephemeral ports
            else:
                dport = 80
                sport = random.randint(49152, 65535)
            
            src_ip = f"192.168.1.{random.randint(2,254)}"
            dst_ip = f"10.0.0.{random.randint(2,254)}"
            
            # Mix of SYN, ACK, and PSH-ACK packets
            if i % 3 == 0:
                flags = "S"  # SYN for new connections
            elif i % 3 == 1:
                flags = "PA"  # PSH-ACK for data transfer
            else:
                flags = "A"  # ACK for existing connections
            
            # Create packet with random payload for data packets
            payload = None
            if flags in ["PA", "A"]:
                payload = os.urandom(random.randint(64, 1024))
            
            pkt = create_packet(src_ip, dst_ip, sport, dport, "TCP", flags, payload)
            if pkt:
                packets.append((pkt, 0))  # 0 for normal traffic
                
        except Exception as e:
            logging.error(f"Error generating normal packet: {str(e)}")
            continue
    
    return packets

def generate_attack_traffic():
    """Generate attack traffic patterns."""
    logging.info("Generating attack traffic patterns...")
    packets = []
    
    # SYN scan
    for i in range(500):
        try:
            src_ip = f"192.168.1.{random.randint(2,254)}"
            dst_ip = f"10.0.0.{random.randint(2,254)}"
            sport = random.randint(1024, 65535)
            dport = random.choice([80, 443, 22, 21, 3306, 5432])  # Common target ports
            
            pkt = create_packet(src_ip, dst_ip, sport, dport, "TCP", "S")
            if pkt:
                packets.append((pkt, 1))  # 1 for attack traffic
                
        except Exception as e:
            logging.error(f"Error generating SYN scan packet: {str(e)}")
            continue
    
    # TCP Connect scan
    for i in range(500):
        try:
            src_ip = f"192.168.1.{random.randint(2,254)}"
            dst_ip = f"10.0.0.{random.randint(2,254)}"
            sport = random.randint(1024, 65535)
            dport = random.choice([80, 443, 22, 21, 3306, 5432])
            
            # Simulate full TCP handshake
            syn_pkt = create_packet(src_ip, dst_ip, sport, dport, "TCP", "S")
            synack_pkt = create_packet(dst_ip, src_ip, dport, sport, "TCP", "SA")
            ack_pkt = create_packet(src_ip, dst_ip, sport, dport, "TCP", "A")
            
            if syn_pkt and synack_pkt and ack_pkt:
                packets.extend([(syn_pkt, 1), (synack_pkt, 1), (ack_pkt, 1)])
                
        except Exception as e:
            logging.error(f"Error generating TCP Connect scan packet: {str(e)}")
            continue
    
    # FIN scan
    for i in range(500):
        try:
            src_ip = f"192.168.1.{random.randint(2,254)}"
            dst_ip = f"10.0.0.{random.randint(2,254)}"
            sport = random.randint(1024, 65535)
            dport = random.choice([80, 443, 22, 21, 3306, 5432])
            
            pkt = create_packet(src_ip, dst_ip, sport, dport, "TCP", "F")
            if pkt:
                packets.append((pkt, 1))
                
        except Exception as e:
            logging.error(f"Error generating FIN scan packet: {str(e)}")
            continue
    
    # NULL scan
    for i in range(500):
        try:
            src_ip = f"192.168.1.{random.randint(2,254)}"
            dst_ip = f"10.0.0.{random.randint(2,254)}"
            sport = random.randint(1024, 65535)
            dport = random.choice([80, 443, 22, 21, 3306, 5432])
            
            pkt = create_packet(src_ip, dst_ip, sport, dport, "TCP", "")  # Empty flags
            if pkt:
                packets.append((pkt, 1))
                
        except Exception as e:
            logging.error(f"Error generating NULL scan packet: {str(e)}")
            continue
    
    # XMAS scan
    for i in range(500):
        try:
            src_ip = f"192.168.1.{random.randint(2,254)}"
            dst_ip = f"10.0.0.{random.randint(2,254)}"
            sport = random.randint(1024, 65535)
            dport = random.choice([80, 443, 22, 21, 3306, 5432])
            
            pkt = create_packet(src_ip, dst_ip, sport, dport, "TCP", "FPU")  # FIN, PUSH, URG
            if pkt:
                packets.append((pkt, 1))
                
        except Exception as e:
            logging.error(f"Error generating XMAS scan packet: {str(e)}")
            continue
    
    # UDP scan
    for i in range(500):
        try:
            src_ip = f"192.168.1.{random.randint(2,254)}"
            dst_ip = f"10.0.0.{random.randint(2,254)}"
            sport = random.randint(1024, 65535)
            dport = random.choice([53, 161, 123, 137, 138])  # Common UDP ports
            
            pkt = create_packet(src_ip, dst_ip, sport, dport, "UDP")
            if pkt:
                packets.append((pkt, 1))
                
        except Exception as e:
            logging.error(f"Error generating UDP scan packet: {str(e)}")
            continue
    
    return packets

def main():
    """Main function to generate training data and train models."""
    try:
        # Generate traffic
        normal_packets = generate_normal_traffic()
        attack_packets = generate_attack_traffic()
        
        # Combine and shuffle packets
        all_packets = normal_packets + attack_packets
        random.shuffle(all_packets)
        
        # Extract features
        classifier = MLNetworkClassifier()
        X = []
        y = []
        
        for packet, label in all_packets:
            features = classifier.extract_features(packet)
            if features is not None:
                X.append(features)
                y.append(label)
        
        if not X:
            raise ValueError("No valid features extracted from packets")
        
        # Convert to numpy arrays
        X = np.vstack(X)
        y = np.array(y)
        
        # Train models
        classifier.train_models(X, y)
        
        # Save models
        classifier.save_models()
        
    except Exception as e:
        logging.error(f"Error in main: {str(e)}")
        raise

if __name__ == "__main__":
    main()