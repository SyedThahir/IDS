# ML-Based Network Intrusion Detection System

A machine learning-based Network Intrusion Detection System (IDS) that uses Random Forest and SVM classifiers to detect various types of network attacks in real-time. The system features both a command-line interface and a modern web dashboard for monitoring and analysis.

## Features

- **Real-time Network Monitoring**: Captures and analyzes network packets in real-time
- **Machine Learning Models**: 
  - Random Forest Classifier (91% accuracy)
  - Support Vector Machine (81% accuracy)
- **Attack Detection**:
  - SYN scans
  - TCP Connect scans
  - FIN scans
  - NULL scans
  - XMAS scans
  - UDP scans
- **Web Dashboard**:
  - Real-time traffic visualization
  - Protocol distribution analysis
  - Detailed alert logging
  - Filtering capabilities
  - System status monitoring
- **Comprehensive Logging**:
  - Alert history
  - Performance metrics
  - System statistics

## Requirements

- Python 3.8+
- Scapy
- Flask
- scikit-learn
- numpy
- pandas

## Installation

1. Clone the repository:
```bash
git clone https://github.com/SyedThahir/IDS.git
cd advanced_ids
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. Ensure you have proper permissions for packet capture:
```bash
sudo chmod +x monitor.py
sudo chmod +x app.py
```

## Usage

1. Start the web dashboard:
```bash
python app.py
```

2. Access the dashboard at:
```
http://localhost:5051
```

3. For command-line monitoring:
```bash
sudo python monitor.py
```

## Dashboard Features

- **Traffic Analysis**: Real-time visualization of network traffic rates
- **Protocol Distribution**: Live breakdown of protocol usage
- **Alert Monitoring**: Real-time alert display with filtering options
- **System Status**: Monitor ML models and processing queue status

## Security Features

- Detection of various scan types:
  - SYN scans (stealth scans)
  - TCP Connect scans
  - FIN scans
  - NULL scans
  - XMAS scans
  - UDP scans
- Rate-based detection
- Pattern-based analysis
- Dynamic threshold adjustment
- Port scanning detection

## Performance

- Processing Rate: ~50 packets/second
- Random Forest Accuracy: 91%
  - False Positive Rate: 6.5%
- SVM Accuracy: 81%
  - False Positive Rate: 2.5%

## Project Structure

```
advanced_ids/
├── app.py              # Web dashboard application
├── ml_ids_core.py      # Core ML and packet processing
├── monitor.py          # Command-line monitoring
├── generate_training_data.py  # Training data generation
├── models/             # Trained ML models
├── logs/              # System logs
└── templates/         # Web dashboard templates
```


## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- scikit-learn for machine learning models
- Scapy for packet capture and analysis
- Flask for web dashboard
- Chart.js for visualizations 
