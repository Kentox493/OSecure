# main.py
import sys
import subprocess
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
import json
from datetime import datetime
import re

class ColorTheme:
    # Main colors
    PRIMARY_DARK = "#1A1B26"      # Dark background
    PRIMARY_LIGHT = "#24283B"     # Panel background
    ACCENT_GREEN = "#73D216"      # Success actions
    ACCENT_RED = "#CC3E44"        # Warning/delete actions
    ACCENT_BLUE = "#2C78BF"       # Info/status
    
    # Text colors
    TEXT_PRIMARY = "#A9B1D6"
    TEXT_BRIGHT = "#C0CAF5"
    TEXT_MUTED = "#565F89"
    
    # Border and panel colors
    BORDER = "#414868"
    PANEL_BG = "rgba(36, 40, 59, 0.9)"
    
    # Status colors
    STATUS_SUCCESS = "#9ECE6A"
    STATUS_WARNING = "#E0AF68"
    STATUS_ERROR = "#F7768E"

class CustomButton(QPushButton):
    def __init__(self, text, color=ColorTheme.PRIMARY_LIGHT, icon=None):
        super().__init__(text)
        self.base_color = color
        if icon:
            self.setIcon(QIcon.fromTheme(icon))
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: {color};
                color: {ColorTheme.TEXT_BRIGHT};
                border: 1px solid {ColorTheme.BORDER};
                padding: 8px 16px;
                border-radius: 4px;
                font-size: 13px;
                min-width: 120px;
            }}
            QPushButton:hover {{
                background-color: {ColorTheme.PRIMARY_LIGHT};
                border-color: {ColorTheme.ACCENT_BLUE};
            }}
            QPushButton:pressed {{
                background-color: {ColorTheme.PRIMARY_DARK};
            }}
            
        """)

class FirewallManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        
    def initUI(self):
        self.setWindowTitle("Professional Cybersecurity Firewall Manager")
        self.setMinimumSize(1200, 800)
        
        # Set window style
        self.setStyleSheet(f"""
            QMainWindow {{
                background-color: {ColorTheme.PRIMARY_DARK};
            }}
            QLabel {{
                color: {ColorTheme.TEXT_PRIMARY};
                font-size: 14px;
            }}
            QGroupBox {{
                color: {ColorTheme.TEXT_BRIGHT};
                border: 1px solid {ColorTheme.BORDER};
                border-radius: 6px;
                margin-top: 1ex;
                font-weight: bold;
                background-color: {ColorTheme.PANEL_BG};
            }}
            QTextEdit {{
                background-color: {ColorTheme.PRIMARY_LIGHT};
                color: {ColorTheme.TEXT_PRIMARY};
                border: 1px solid {ColorTheme.BORDER};
                border-radius: 4px;
                padding: 8px;
                font-family: 'Consolas', monospace;
            }}
        """)
        
        # Central Widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Header
        header = self.create_header()
        main_layout.addWidget(header)
        
        # Stats Dashboard
        stats_dashboard = self.create_stats_dashboard()
        main_layout.addWidget(stats_dashboard)
        
        # Main Content Area
        content = QHBoxLayout()
        
        # Rules Panel
        rules_panel = self.create_rules_panel()
        content.addWidget(rules_panel, stretch=2)
        
        # Status Panel
        status_panel = self.create_status_panel()
        content.addWidget(status_panel, stretch=1)
        
        main_layout.addLayout(content)
        
        # Initialize status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.setStyleSheet(f"""
            QStatusBar {{
                color: {ColorTheme.TEXT_BRIGHT};
                background-color: {ColorTheme.PRIMARY_LIGHT};
                border-top: 1px solid {ColorTheme.BORDER};
            }}
        """)
        
        # Initial refresh
        self.refresh_status()
        
    def create_header(self):
        header = QWidget()
        header_layout = QHBoxLayout(header)
        
        title = QLabel("🛡️ OSecure : Firewall Manager")
        title.setStyleSheet(f"""
            font-size: 24px;
            font-weight: bold;
            color: {ColorTheme.TEXT_BRIGHT};
            padding: 10px;
        """)
        header_layout.addWidget(title, alignment=Qt.AlignCenter)
        
        return header
        
    def create_stats_dashboard(self):
        stats_widget = QWidget()
        stats_layout = QHBoxLayout(stats_widget)
        
        stats = [
            ("Active Rules", "0", "🔒"),
            ("Protected Ports", "0", "🌐"),
            ("Blocked Attacks", "0", "🚫")
        ]
        
        for title, value, icon in stats:
            self.create_stat_card(title, value, icon, stats_layout)
            
        return stats_widget
        
    def create_stat_card(self, title, value, icon, parent_layout):
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background-color: {ColorTheme.PRIMARY_LIGHT};
                border: 1px solid {ColorTheme.BORDER};
                border-radius: 6px;
                padding: 15px;
            }}
        """)
        
        layout = QVBoxLayout(card)
        
        header = QLabel(f"{icon} {title}")
        header.setStyleSheet(f"""
            color: {ColorTheme.TEXT_BRIGHT};
            font-size: 16px;
            font-weight: bold;
        """)
        layout.addWidget(header)
        
        value_label = QLabel(value)
        value_label.setStyleSheet(f"""
            color: {ColorTheme.ACCENT_GREEN};
            font-size: 24px;
            font-weight: bold;
        """)
        layout.addWidget(value_label, alignment=Qt.AlignCenter)
        
        parent_layout.addWidget(card)
        return value_label
        
    def create_rules_panel(self):
        rules_scroll = QScrollArea()
        rules_scroll.setWidgetResizable(True)
        rules_scroll.setStyleSheet("border: none;")
        
        rules_widget = QWidget()
        rules_layout = QVBoxLayout(rules_widget)
        
        # Basic Protection Rules
        self.create_rule_group(rules_layout, "🛡️ Basic Protection", [
            ("Block All Incoming", "iptables -P INPUT DROP"),
            ("Allow Established", "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT"),
            ("Allow Loopback", "iptables -A INPUT -i lo -j ACCEPT")
        ])
        
        # Network Services Rules
        self.create_rule_group(rules_layout, "🌐 Network Services", [
            ("Allow HTTP/HTTPS", """
                iptables -A INPUT -p tcp --dport 80 -j ACCEPT
                iptables -A INPUT -p tcp --dport 443 -j ACCEPT
            """),
            ("Allow DNS", "iptables -A INPUT -p udp --dport 53 -j ACCEPT"),
            ("Allow Mail", """
                iptables -A INPUT -p tcp --dport 25 -j ACCEPT
                iptables -A INPUT -p tcp --dport 587 -j ACCEPT
                iptables -A INPUT -p tcp --dport 993 -j ACCEPT
            """)
        ])
        
        # Security Rules
        self.create_rule_group(rules_layout, "🔒 Advanced Security", [
            ("Block Invalid Packets", "iptables -A INPUT -m state --state INVALID -j DROP"),
            ("Anti Port Scanning", """
                iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
                iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
            """),
            ("Rate Limit Connections", """
                iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 20 -j DROP
                iptables -A INPUT -p tcp --dport 443 -m connlimit --connlimit-above 20 -j DROP
            """)
        ])
        # SSH Protection Rules
        self.create_rule_group(rules_layout, "🔑 SSH Protection", [
            ("Secure SSH", """
                iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH
                iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 --rttl --name SSH -j DROP
            """),
            ("Allow SSH from Trusted IPs", """
                iptables -A INPUT -p tcp --dport 22 -s 192.168.1.0/24 -j ACCEPT
                iptables -A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT
            """),
            ("SSH Brute Force Protection", """
                iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set
                iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP
            """)
        ])

        # DDoS Protection Rules
        self.create_rule_group(rules_layout, "🛡️ DDoS Protection", [
            ("SYN Flood Protection", """
                iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
                iptables -A INPUT -p tcp --syn -j DROP
            """),
            ("ICMP Flood Protection", """
                iptables -A INPUT -p icmp -m limit --limit 1/s --limit-burst 1 -j ACCEPT
                iptables -A INPUT -p icmp -j DROP
            """),
            ("UDP Flood Protection", """
                iptables -A INPUT -p udp -m limit --limit 10/s -j ACCEPT
                iptables -A INPUT -p udp -j DROP
            """),
            ("HTTP DoS Protection", """
                iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT
                iptables -A INPUT -p tcp --dport 443 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT
            """)
        ])

        # Application Layer Protection
        self.create_rule_group(rules_layout, "📱 Application Protection", [
            ("Database Ports", """
                iptables -A INPUT -p tcp --dport 3306 -s 192.168.1.0/24 -j ACCEPT
                iptables -A INPUT -p tcp --dport 5432 -s 192.168.1.0/24 -j ACCEPT
                iptables -A INPUT -p tcp --dport 27017 -s 192.168.1.0/24 -j ACCEPT
            """),
            ("Web Application Ports", """
                iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
                iptables -A INPUT -p tcp --dport 8443 -j ACCEPT
                iptables -A INPUT -p tcp --dport 3000:3010 -j ACCEPT
            """),
            ("Cache & Message Queues", """
                iptables -A INPUT -p tcp --dport 6379 -s 127.0.0.1 -j ACCEPT
                iptables -A INPUT -p tcp --dport 5672 -s 127.0.0.1 -j ACCEPT
            """)
        ])

        # Geographic Blocking
        self.create_rule_group(rules_layout, "🌍 Geographic Protection", [
            ("Block High-Risk Countries", """
                iptables -A INPUT -m geoip --src-cc CN,RU,NK -j DROP
                iptables -A INPUT -m geoip --src-cc IR,KP -j DROP
            """),
            ("Allow Specific Countries", """
                iptables -A INPUT -m geoip --src-cc US,CA,GB,FR,DE -j ACCEPT
                iptables -A INPUT -m geoip --src-cc JP,AU,NZ -j ACCEPT
            """)
        ])

        # Protocol Security
        self.create_rule_group(rules_layout, "🔐 Protocol Security", [
            ("Block Telnet", "iptables -A INPUT -p tcp --dport 23 -j DROP"),
            ("Block FTP", """
                iptables -A INPUT -p tcp --dport 20 -j DROP
                iptables -A INPUT -p tcp --dport 21 -j DROP
            """),
            ("Secure SNMP", """
                iptables -A INPUT -p udp --dport 161 -s 192.168.1.0/24 -j ACCEPT
                iptables -A INPUT -p udp --dport 161 -j DROP
            """),
            ("Block Common Malware Ports", """
                iptables -A INPUT -p tcp --dport 135 -j DROP
                iptables -A INPUT -p udp --dport 137:139 -j DROP
                iptables -A INPUT -p tcp --dport 445 -j DROP
            """)
        ])

        # Custom Security Measures
        self.create_rule_group(rules_layout, "🎯 Custom Security", [
            ("Log Suspicious Traffic", """
                iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "SUSPICIOUS_DROP: " --log-level 7
            """),
            ("Block IP Spoofing", """
                iptables -A INPUT -s 127.0.0.0/8 ! -i lo -j DROP
                iptables -A INPUT -s 0.0.0.0/8 -j DROP
                iptables -A INPUT -s 169.254.0.0/16 -j DROP
                iptables -A INPUT -s 172.16.0.0/12 -j DROP
                iptables -A INPUT -s 192.168.0.0/16 -j DROP
                iptables -A INPUT -s 224.0.0.0/4 -j DROP
                iptables -A INPUT -s 240.0.0.0/5 -j DROP
            """),
            ("Fragment Protection", """
                iptables -A INPUT -f -j DROP
            """),
            ("XMAS Packet Drop", """
                iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
                iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
            """)
        ])
        rules_scroll.setWidget(rules_widget)
        return rules_scroll
        
    def create_rule_group(self, parent_layout, title, rules):
        group = QGroupBox(title)
        group_layout = QVBoxLayout(group)
        
        for rule_name, rule_cmd in rules:
            rule_layout = QHBoxLayout()
            
            enable_btn = CustomButton(f"Enable {rule_name}")
            disable_btn = CustomButton(f"Disable {rule_name}")

            enable_btn.clicked.connect(lambda checked, cmd=rule_cmd: self.apply_rule(cmd))
            disable_btn.clicked.connect(lambda checked, cmd=rule_cmd: self.remove_rule(cmd))
            
            rule_layout.addWidget(enable_btn)
            rule_layout.addWidget(disable_btn)
            group_layout.addLayout(rule_layout)
            
        parent_layout.addWidget(group)
        
    def create_status_panel(self):
        status_widget = QWidget()
        status_layout = QVBoxLayout(status_widget)
        
        # Status Display
        status_header = QLabel("📊 Current Firewall Status")
        status_header.setStyleSheet(f"""
            font-size: 18px;
            font-weight: bold;
            color: {ColorTheme.TEXT_BRIGHT};
            margin-bottom: 10px;
        """)
        status_layout.addWidget(status_header)
        
        self.status_display = QTextEdit()
        self.status_display.setReadOnly(True)
        status_layout.addWidget(self.status_display)
        
        # Control Buttons
        control_layout = QHBoxLayout()
        
        refresh_btn = CustomButton("🔄 Refresh Status")
        refresh_btn.clicked.connect(self.refresh_status)
        control_layout.addWidget(refresh_btn)
        
        clear_btn = CustomButton("🗑️ Clear Rules")
        clear_btn.clicked.connect(self.confirm_clear_rules)
        control_layout.addWidget(clear_btn)
        
        status_layout.addLayout(control_layout)
        
        # Log Area
        log_header = QLabel("📝 System Log")
        log_header.setStyleSheet(f"""
            font-size: 18px;
            font-weight: bold;
            color: {ColorTheme.TEXT_BRIGHT};
            margin-bottom: 10px;
        """)
        status_layout.addWidget(log_header)
        
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setMaximumHeight(200)
        status_layout.addWidget(self.log_area)
        
        return status_widget
        
    def apply_rule(self, rule):
        try:
            for cmd in rule.strip().split('\n'):
                cmd = cmd.strip()
                if cmd:
                    subprocess.run(['sudo'] + cmd.split(), check=True)
            self.log_message("✅ Rule applied successfully")
            self.refresh_status()
        except subprocess.CalledProcessError as e:
            self.log_message(f"❌ Error applying rule: {str(e)}")
            
    def remove_rule(self, rule):
        try:
            for cmd in rule.strip().split('\n'):
                cmd = cmd.strip()
                if cmd:
                    cmd = cmd.replace("-A", "-D")
                    subprocess.run(['sudo'] + cmd.split(), check=True)
            self.log_message("✅ Rule removed successfully")
            self.refresh_status()
        except subprocess.CalledProcessError as e:
            self.log_message(f"❌ Error removing rule: {str(e)}")
            
    def refresh_status(self):
        try:
            result = subprocess.run(['sudo', 'iptables', '-L', '-n', '--line-numbers'],
                                 capture_output=True, text=True, check=True)
            self.status_display.setText(result.stdout)
            self.update_stats()
            self.status_bar.showMessage("Status refreshed successfully")
        except subprocess.CalledProcessError as e:
            self.log_message(f"❌ Error refreshing status: {str(e)}")
            
    def confirm_clear_rules(self):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Warning)
        msg.setText("Are you sure you want to clear all firewall rules?")
        msg.setInformativeText("This will remove all current firewall rules and might affect system security.")
        msg.setWindowTitle("Confirm Clear Rules")
        msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        msg.setStyleSheet(f"""
            QMessageBox {{
                background-color: {ColorTheme.PRIMARY_LIGHT};
                color: {ColorTheme.TEXT_BRIGHT};
            }}
            QLabel {{
                color: {ColorTheme.TEXT_BRIGHT};
            }}
            QPushButton {{
                background-color: {ColorTheme.PRIMARY_DARK};
                color: {ColorTheme.TEXT_BRIGHT};
                border: 1px solid {ColorTheme.BORDER};
                padding: 5px 15px;
                border-radius: 3px;
            }}
            QPushButton:hover {{
                border-color: {ColorTheme.ACCENT_BLUE};
            }}
        """)
        
        if msg.exec_() == QMessageBox.Yes:
            self.clear_rules()
            
    def clear_rules(self):
        try:
            subprocess.run(['sudo', 'iptables', '-F'], check=True)
            self.log_message("🗑️ All rules cleared")
            self.refresh_status()
        except subprocess.CalledProcessError as e:
            self.log_message(f"❌ Error clearing rules: {str(e)}")
            
    def update_stats(self):
        try:
            result = subprocess.run(['sudo', 'iptables', '-L', '-n'],
                                 capture_output=True, text=True, check=True)
            
            active_rules = len(re.findall(r'Chain \w+ \(policy \w+\)', result.stdout))
            blocked = len(re.findall(r'DROP', result.stdout))
            protected = len(re.findall(r'dpt:\d+', result.stdout))
            
            # Update stat cards (assuming they're the first, third, and fifth QLabels)
            labels = self.findChildren(QLabel)
            stat_labels = [l for l in labels if l.text().isdigit()]
            
            if len(stat_labels) >= 3:
                stat_labels[0].setText(str(active_rules))
                stat_labels[1].setText(str(protected))
                stat_labels[2].setText(str(blocked))
                
        except subprocess.CalledProcessError as e:
            self.log_message(f"❌ Error updating stats: {str(e)}")
            
    def log_message(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_area.append(f"[{timestamp}] {message}")
        # Auto-scroll to bottom
        self.log_area.verticalScrollBar().setValue(
            self.log_area.verticalScrollBar().maximum()
        )

def main():
    # Enable high DPI scaling
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps)
    
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle("Fusion")
    
    # Set application font
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    
    window = FirewallManager()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
