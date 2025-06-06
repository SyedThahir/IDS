#!/usr/bin/env python3
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
from scapy.all import *
from scapy.layers.inet import TCP, IP, UDP
import joblib
import logging
import os
import time

class MLNetworkClassifier:
    def __init__(self):
        self.rf_model = None
        self.svm_model = None
        self.scaler = StandardScaler()
        # Enhanced feature set
        self.feature_names = [
            'packet_size', 'tcp_flags', 'port_number',
            'protocol_type', 'packet_rate', 'byte_rate',
            'avg_packet_size', 'packet_interval',
            'is_privileged_port', 'payload_size',
            'header_length', 'window_size',
            'is_common_service_port'
        ]
        
        # Track packet history for time-based features
        self.packet_history = []
        self.packet_history_ports = set()  # Track unique ports for scan detection
        self.max_history = 1000
        self.common_service_ports = {20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389}
        
        # Configure logging
        logging.basicConfig(
            filename='ml_ids.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # Load pre-trained models if they exist
        self.load_models()

    def update_packet_history(self, packet, features):
        """Update packet history for time-based features."""
        current_time = time.time()
        self.packet_history.append({
            'time': current_time,
            'size': features['packet_size'],
            'features': features
        })
        
        # Keep history within size limit
        if len(self.packet_history) > self.max_history:
            self.packet_history.pop(0)

    def extract_features(self, packet):
        """Extract enhanced features from a network packet."""
        try:
            if packet is None:
                return None
                
            features = {}
            
            # Basic packet features with safe defaults
            features['packet_size'] = float(len(packet)) if packet else 0.0
            features['protocol_type'] = 0.0  # Default for unknown
            features['tcp_flags'] = 0.0  # Default for non-TCP
            features['port_number'] = 0.0  # Default
            features['is_privileged_port'] = 0.0
            features['payload_size'] = 0.0
            features['header_length'] = 0.0
            features['window_size'] = 0.0
            features['is_common_service_port'] = 0.0
            features['packet_rate'] = 0.0
            features['byte_rate'] = 0.0
            features['avg_packet_size'] = 0.0
            features['packet_interval'] = 0.0
            
            # Extract IP layer features
            if IP in packet:
                ip_pkt = packet[IP]
                if hasattr(ip_pkt, 'ihl') and ip_pkt.ihl is not None:
                    try:
                        features['header_length'] = float(ip_pkt.ihl * 4)
                    except (TypeError, ValueError):
                        features['header_length'] = 0.0
                
                # Extract transport layer features
                if TCP in packet:
                    tcp_pkt = packet[TCP]
                    features['protocol_type'] = 6.0  # TCP
                    
                    if hasattr(tcp_pkt, 'dport') and tcp_pkt.dport is not None:
                        try:
                            dport = int(tcp_pkt.dport)
                            features['port_number'] = float(dport)
                            features['is_privileged_port'] = 1.0 if dport < 1024 else 0.0
                            features['is_common_service_port'] = 1.0 if dport in self.common_service_ports else 0.0
                        except (TypeError, ValueError):
                            pass
                    
                    if hasattr(tcp_pkt, 'window') and tcp_pkt.window is not None:
                        try:
                            features['window_size'] = float(tcp_pkt.window)
                        except (TypeError, ValueError):
                            features['window_size'] = 0.0
                    
                    # Handle TCP flags numerically
                    if hasattr(tcp_pkt, 'flags'):
                        try:
                            # Store flags as string representation
                            flags_str = str(tcp_pkt.flags)
                            # Convert common flag combinations to numeric values
                            if 'S' in flags_str:  # SYN
                                features['tcp_flags'] = 2.0
                            elif 'SA' in flags_str:  # SYN-ACK
                                features['tcp_flags'] = 18.0
                            elif 'A' in flags_str:  # ACK
                                features['tcp_flags'] = 16.0
                            elif 'F' in flags_str:  # FIN
                                features['tcp_flags'] = 1.0
                            elif 'R' in flags_str:  # RST
                                features['tcp_flags'] = 4.0
                            elif 'P' in flags_str:  # PSH
                                features['tcp_flags'] = 8.0
                        except (TypeError, ValueError, AttributeError):
                            features['tcp_flags'] = 0.0
                    
                elif UDP in packet:
                    udp_pkt = packet[UDP]
                    features['protocol_type'] = 17.0  # UDP
                    
                    if hasattr(udp_pkt, 'dport') and udp_pkt.dport is not None:
                        try:
                            dport = int(udp_pkt.dport)
                            features['port_number'] = float(dport)
                            features['is_privileged_port'] = 1.0 if dport < 1024 else 0.0
                            features['is_common_service_port'] = 1.0 if dport in self.common_service_ports else 0.0
                        except (TypeError, ValueError):
                            pass
                
                # Calculate payload size
                if Raw in packet:
                    raw_pkt = packet[Raw]
                    if hasattr(raw_pkt, 'load') and raw_pkt.load is not None:
                        try:
                            features['payload_size'] = float(len(raw_pkt.load))
                        except (TypeError, ValueError):
                            features['payload_size'] = 0.0
            
            # Update packet history for time-based features
            current_time = time.time()
            self.packet_history.append((current_time, features['packet_size']))
            if len(self.packet_history) > self.max_history:
                self.packet_history.pop(0)
            
            # Calculate time-based features if we have enough history
            if len(self.packet_history) > 1:
                try:
                    time_window = current_time - self.packet_history[0][0]
                    if time_window > 0:
                        total_bytes = sum(size for _, size in self.packet_history)
                        features['packet_rate'] = float(len(self.packet_history)) / time_window
                        features['byte_rate'] = float(total_bytes) / time_window
                        features['avg_packet_size'] = float(total_bytes) / len(self.packet_history)
                        
                        # Calculate average time between packets
                        intervals = []
                        for i in range(1, len(self.packet_history)):
                            interval = self.packet_history[i][0] - self.packet_history[i-1][0]
                            intervals.append(interval)
                        if intervals:
                            features['packet_interval'] = float(sum(intervals)) / len(intervals)
                except (TypeError, ValueError, ZeroDivisionError):
                    # Keep default values if calculations fail
                    pass
            
            # Convert features to numpy array in consistent order
            feature_vector = np.array([features[name] for name in self.feature_names], dtype=np.float64)
            return feature_vector.reshape(1, -1)  # Return 2D array with shape (1, n_features)
            
        except Exception as e:
            logging.error(f"Error extracting features: {str(e)}")
            return None

    def train_models(self, X, y):
        """Train both Random Forest and SVM models with optimized parameters."""
        try:
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
            
            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Train Random Forest with optimized parameters
            self.rf_model = RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                min_samples_split=10,
                min_samples_leaf=4,
                max_features='sqrt',
                class_weight='balanced',
                random_state=42,
                n_jobs=-1  # Use all CPU cores
            )
            self.rf_model.fit(X_train_scaled, y_train)
            
            # Train SVM with optimized parameters
            self.svm_model = SVC(
                kernel='rbf',
                C=10.0,
                gamma='scale',
                class_weight='balanced',
                probability=True,
                random_state=42
            )
            self.svm_model.fit(X_train_scaled, y_train)
            
            # Evaluate models
            self._evaluate_model(self.rf_model, X_test_scaled, y_test, "Random Forest")
            self._evaluate_model(self.svm_model, X_test_scaled, y_test, "SVM")
            
            # Save models
            self.save_models()
            
        except Exception as e:
            logging.error(f"Error training models: {str(e)}")
            raise

    def _evaluate_model(self, model, X_test, y_test, model_name):
        """Evaluate model performance with focus on false positives."""
        y_pred = model.predict(X_test)
        
        # Generate detailed metrics
        logging.info(f"\n{model_name} Performance Metrics:")
        logging.info("\nConfusion Matrix:")
        logging.info(confusion_matrix(y_test, y_pred))
        logging.info("\nClassification Report:")
        logging.info(classification_report(y_test, y_pred))
        
        # Calculate false positive rate
        tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
        fpr = fp / (fp + tn)
        logging.info(f"False Positive Rate: {fpr:.4f}")

    def predict(self, packet):
        """Predict if a packet is malicious using ensemble of models with threshold tuning."""
        features = self.extract_features(packet)
        if features is None:
            return False
            
        try:
            # Scale features
            features_scaled = self.scaler.transform(features)
            
            # Get predictions from both models
            rf_pred = self.rf_model.predict_proba(features_scaled)[0]
            svm_pred = self.svm_model.predict_proba(features_scaled)[0]
            
            # Weighted ensemble prediction
            # Give more weight to Random Forest (0.6) than SVM (0.4)
            weighted_prob = (0.6 * rf_pred[1] + 0.4 * svm_pred[1])
            
            # Dynamic threshold based on packet characteristics
            base_threshold = 0.85  # Base threshold for normal traffic
            
            # Get packet protocol and flags
            if TCP in packet:
                tcp_flags = str(packet[TCP].flags)
                
                # Adjust threshold based on TCP flags and patterns
                if 'S' in tcp_flags and 'A' not in tcp_flags:  # SYN scan
                    threshold = base_threshold * 0.9
                elif 'F' in tcp_flags:  # FIN scan
                    threshold = base_threshold * 0.85
                elif 'R' in tcp_flags:  # RST scan
                    threshold = base_threshold * 0.85
                elif not tcp_flags:  # NULL scan
                    threshold = base_threshold * 0.8
                elif 'F' in tcp_flags and 'P' in tcp_flags and 'U' in tcp_flags:  # XMAS scan
                    threshold = base_threshold * 0.8
                elif 'A' in tcp_flags and len(tcp_flags) == 1:  # ACK scan
                    threshold = base_threshold * 0.85
                else:  # Other TCP traffic
                    threshold = base_threshold
                    
                # Check for port scanning patterns
                if hasattr(packet[TCP], 'dport'):
                    dport = packet[TCP].dport
                    if dport in self.packet_history_ports:
                        # Repeated attempts to different ports
                        threshold = base_threshold * 0.85
                    self.packet_history_ports.add(dport)
                    
            elif UDP in packet:
                # UDP scans
                threshold = base_threshold * 0.9
            else:
                threshold = base_threshold
            
            # Rate-based detection
            if self.calculate_packet_rate() > 100:  # High packet rate
                threshold *= 0.9
            
            return weighted_prob > threshold
            
        except Exception as e:
            logging.error(f"Error in prediction: {str(e)}")
            return False

    def save_models(self):
        """Save trained models and scaler."""
        try:
            joblib.dump(self.rf_model, 'models/rf_model.pkl')
            joblib.dump(self.svm_model, 'models/svm_model.pkl')
            joblib.dump(self.scaler, 'models/scaler.pkl')
            logging.info("Models saved successfully")
        except Exception as e:
            logging.error(f"Error saving models: {str(e)}")

    def load_models(self):
        """Load pre-trained models and scaler."""
        try:
            if os.path.exists('models/rf_model.pkl'):
                self.rf_model = joblib.load('models/rf_model.pkl')
                self.svm_model = joblib.load('models/svm_model.pkl')
                self.scaler = joblib.load('models/scaler.pkl')
                logging.info("Models loaded successfully")
            else:
                logging.warning("No pre-trained models found")
        except Exception as e:
            logging.error(f"Error loading models: {str(e)}")

    # Helper methods for feature extraction
    def calculate_packet_rate(self):
        """Calculate packet rate using a sliding window."""
        try:
            # Using a 1-second window for rate calculation
            current_time = time.time()
            # Count packets in the last second
            recent_packets = 10  # Simplified for demonstration
            return float(recent_packets)
        except Exception as e:
            logging.error(f"Error calculating packet rate: {str(e)}")
            return 1.0

    def calculate_byte_rate(self):
        """Calculate byte rate using a sliding window."""
        try:
            # Using a 1-second window for rate calculation
            current_time = time.time()
            # Calculate bytes in the last second
            recent_bytes = 1500  # Average packet size for demonstration
            return float(recent_bytes)
        except Exception as e:
            logging.error(f"Error calculating byte rate: {str(e)}")
            return 1500.0

    def calculate_avg_packet_size(self):
        """Calculate average packet size."""
        try:
            # Using last 10 packets for average
            recent_sizes = [1500]  # Simplified for demonstration
            return float(sum(recent_sizes) / len(recent_sizes))
        except Exception as e:
            logging.error(f"Error calculating average packet size: {str(e)}")
            return 1500.0

    def calculate_packet_interval(self):
        """Calculate average time between packets."""
        try:
            # Calculate average interval between last 10 packets
            recent_intervals = [0.1]  # Simplified for demonstration
            return float(sum(recent_intervals) / len(recent_intervals))
        except Exception as e:
            logging.error(f"Error calculating packet interval: {str(e)}")
            return 0.1 