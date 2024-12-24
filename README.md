# 🛡️ OSecure - Open Source Secure Firewall

A modern, user-friendly GUI application for managing Linux firewall rules using iptables.

## Features

- 🛡️ Comprehensive firewall rule management
- 📊 Real-time status monitoring
- 🌍 Geographic-based filtering
- 🔒 DDoS protection
- 🚫 Advanced security measures
- 📱 Application layer protection
- 📝 System logging

## Prerequisites

- Linux operating system
- Python 3.8+
- `sudo` privileges for iptables management
- iptables installed and configured
- PyQt5

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Kentox493/OSecure.git
cd OSecure
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
sudo python gui.py
```

Note: sudo privileges are required for iptables operations.

## Usage

1. Launch the application with sudo privileges
2. Use the interface to enable/disable various firewall rules
3. Monitor the system log for rule application status
4. View current firewall status in the status panel
5. Use the refresh button to update current status

## Security Features

- Basic Protection Rules
- Network Services Protection
- SSH Security
- DDoS Protection
- Geographic Filtering
- Application Layer Security
- Protocol Security
- Custom Security Measures

## Acknowledgments

- Built with PyQt5
- Uses iptables for firewall management
