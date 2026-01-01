"""
Advanced Port Scanner - Complete Standalone GUI
Project 3 - Cybersecurity Python Roadmap
Author: bnahmedsoumaya00
Date: December 31, 2025

This is a complete standalone version with all functionality built-in.
No external dependencies needed - everything in one file!
"""

import socket
import ipaddress
import threading
import time
import csv
import json
from datetime import datetime
from tkinter import *
from tkinter import ttk, messagebox, scrolledtext, filedialog
from queue import Queue
from collections import defaultdict


# ============================================================================
# COMMON PORTS AND SERVICES DATABASE
# ============================================================================

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 27017: "MongoDB", 6379: "Redis",
    9200: "Elasticsearch", 5601: "Kibana", 3000: "Grafana"
}

PORT_CATEGORIES = {
    'critical': [21, 22, 23, 3389, 5900],
    'web': [80, 443, 8080, 8443],
    'database': [3306, 5432, 27017, 6379, 9200],
    'email': [25, 110, 143, 465, 587, 993, 995],
    'file_sharing': [445, 139, 2049],
}


# ============================================================================
# PORT SCANNER ENGINE
# ============================================================================

class PortScanner:
    """Advanced port scanner with multithreading support"""
    
    def __init__(self, timeout=1.0, max_threads=100):
        self.timeout = timeout
        self.max_threads = max_threads
        self.results = defaultdict(list)
        self.lock = threading.Lock()
        self.scan_start_time = None
        self.scan_end_time = None
        self.stop_flag = False
    
    def scan_port(self, ip, port):
        """Scan a single port on a given IP"""
        if self.stop_flag:
            return None
            
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                service_name = COMMON_PORTS.get(port, "Unknown")
                banner = self.grab_banner(ip, port)
                
                return {
                    'port': port,
                    'state': 'open',
                    'service': service_name,
                    'banner': banner
                }
        except:
            pass
        
        return None
    
    def grab_banner(self, ip, port, timeout=2):
        """Attempt to grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                sock.close()
                return banner[:100]
            except:
                sock.close()
                return ""
        except:
            return ""
    
    def worker(self, queue, ip):
        """Worker thread for scanning ports"""
        while not queue.empty() and not self.stop_flag:
            try:
                port = queue.get()
                result = self.scan_port(ip, port)
                
                if result:
                    with self.lock:
                        self.results[ip].append(result)
                
                queue.task_done()
            except:
                queue.task_done()
    
    def scan_host(self, ip, ports):
        """Scan multiple ports on a single host using multithreading"""
        queue = Queue()
        for port in ports:
            queue.put(port)
        
        threads = []
        num_threads = min(self.max_threads, len(ports))
        
        for _ in range(num_threads):
            thread = threading.Thread(target=self.worker, args=(queue, ip))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        queue.join()
        return self.results[ip]
    
    def scan_range(self, ip_range, ports):
        """Scan multiple hosts in a range"""
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            self.scan_start_time = time.time()
            
            for ip in network.hosts():
                if self.stop_flag:
                    break
                ip_str = str(ip)
                self.scan_host(ip_str, ports)
            
            self.scan_end_time = time.time()
            return self.results
            
        except ValueError as e:
            return {}
    
    def stop(self):
        """Stop the scan"""
        self.stop_flag = True
    
    def get_scan_duration(self):
        """Get scan duration in seconds"""
        if self.scan_start_time and self.scan_end_time:
            return self.scan_end_time - self.scan_start_time
        return 0


# ============================================================================
# REPORT GENERATOR
# ============================================================================

class ReportGenerator:
    """Generate scan reports in various formats"""
    
    @staticmethod
    def generate_terminal_report(results, duration=0):
        """Generate formatted terminal report"""
        report = []
        report.append("\n" + "="*70)
        report.append("                    PORT SCAN RESULTS")
        report.append("="*70)
        report.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Scan Duration: {duration:.2f} seconds")
        report.append("="*70)
        
        total_hosts = len(results)
        total_open_ports = sum(len(ports) for ports in results.values())
        
        report.append(f"\nHosts Scanned: {total_hosts}")
        report.append(f"Total Open Ports: {total_open_ports}")
        report.append("")
        
        if not results or total_open_ports == 0:
            report.append("No open ports found.")
            return "\n".join(report)
        
        for ip, ports in sorted(results.items()):
            if not ports:
                continue
                
            report.append(f"\n{'─'*70}")
            report.append(f"🎯 Host: {ip}")
            report.append(f"{'─'*70}")
            report.append(f"{'Port':<8} {'State':<10} {'Service':<20} {'Banner':<30}")
            report.append("─"*70)
            
            sorted_ports = sorted(ports, key=lambda x: x['port'])
            
            for port_info in sorted_ports:
                port = port_info['port']
                state = port_info['state']
                service = port_info['service']
                banner = port_info.get('banner', '')[:30]
                
                report.append(f"{port:<8} {state:<10} {service:<20} {banner:<30}")
            
            report.append("")
        
        report.append("="*70)
        report.append("Scan Complete!")
        report.append("="*70)
        
        return "\n".join(report)
    
    @staticmethod
    def save_csv_report(results, filename='scan_results.csv'):
        """Save results to CSV file"""
        try:
            with open(filename, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['IP Address', 'Port', 'State', 'Service', 'Banner'])
                
                for ip, ports in sorted(results.items()):
                    for port_info in sorted(ports, key=lambda x: x['port']):
                        writer.writerow([
                            ip,
                            port_info['port'],
                            port_info['state'],
                            port_info['service'],
                            port_info.get('banner', '')
                        ])
            return True
        except:
            return False
    
    @staticmethod
    def save_json_report(results, duration=0, filename='scan_results.json'):
        """Save results to JSON file"""
        try:
            report_data = {
                'scan_info': {
                    'timestamp': datetime.now().isoformat(),
                    'duration': duration,
                    'total_hosts': len(results),
                    'total_open_ports': sum(len(ports) for ports in results.values())
                },
                'results': dict(results)
            }
            
            with open(filename, 'w') as f:
                json.dump(report_data, f, indent=4)
            
            return True
        except:
            return False
    
    @staticmethod
    def save_html_report(results, duration=0, filename='scan_results.html'):
        """Save results to HTML file"""
        try:
            html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Port Scan Results</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        .summary {{
            background-color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .summary-item {{
            display: inline-block;
            margin: 10px 20px 10px 0;
        }}
        .host-section {{
            margin: 30px 0;
            border: 1px solid #ddd;
            border-radius: 5px;
            overflow: hidden;
        }}
        .host-header {{
            background-color: #3498db;
            color: white;
            padding: 15px;
            font-size: 1.2em;
            font-weight: bold;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th {{
            background-color: #34495e;
            color: white;
            padding: 12px;
            text-align: left;
        }}
        td {{
            padding: 12px;
            border-bottom: 1px solid #ddd;
        }}
        tr:hover {{
            background-color: #f9f9f9;
        }}
        .port-open {{
            color: #27ae60;
            font-weight: bold;
        }}
        .critical {{
            background-color: #ffe6e6;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Port Scan Results</h1>
        
        <div class="summary">
            <div class="summary-item">
                <strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            </div>
            <div class="summary-item">
                <strong>Duration:</strong> {duration:.2f}s
            </div>
            <div class="summary-item">
                <strong>Hosts:</strong> {len(results)}
            </div>
            <div class="summary-item">
                <strong>Open Ports:</strong> {sum(len(ports) for ports in results.values())}
            </div>
        </div>
"""
            
            if not results:
                html += "<p>No open ports found.</p>"
            else:
                for ip, ports in sorted(results.items()):
                    if not ports:
                        continue
                    
                    html += f"""
        <div class="host-section">
            <div class="host-header">🎯 Host: {ip} ({len(ports)} open ports)</div>
            <table>
                <tr>
                    <th>Port</th>
                    <th>State</th>
                    <th>Service</th>
                    <th>Banner</th>
                </tr>
"""
                    
                    sorted_ports = sorted(ports, key=lambda x: x['port'])
                    for port_info in sorted_ports:
                        port = port_info['port']
                        is_critical = port in PORT_CATEGORIES['critical']
                        row_class = 'critical' if is_critical else ''
                        
                        html += f"""
                <tr class="{row_class}">
                    <td><strong>{port}</strong></td>
                    <td><span class="port-open">{port_info['state']}</span></td>
                    <td>{port_info['service']}</td>
                    <td>{port_info.get('banner', '')[:50]}</td>
                </tr>
"""
                    
                    html += """
            </table>
        </div>
"""
            
            html += """
    </div>
</body>
</html>
"""
            
            with open(filename, 'w') as f:
                f.write(html)
            
            return True
        except:
            return False


# ============================================================================
# PORT PARSING UTILITIES
# ============================================================================

def parse_port_range(port_string):
    """Parse port range string into list of ports"""
    ports = set()
    
    if port_string.lower() == 'common':
        return sorted(COMMON_PORTS.keys())
    elif port_string.lower() == 'all':
        return list(range(1, 65536))
    
    for part in port_string.split(','):
        part = part.strip()
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                ports.update(range(start, end + 1))
            except:
                pass
        else:
            try:
                ports.add(int(part))
            except:
                pass
    
    return sorted(ports)


def validate_ip(ip_string):
    """Validate IP address or CIDR range"""
    try:
        ipaddress.ip_network(ip_string, strict=False)
        return True
    except ValueError:
        try:
            ipaddress.ip_address(ip_string)
            return True
        except ValueError:
            return False


# ============================================================================
# GUI APPLICATION
# ============================================================================

class PortScannerGUI:
    """Complete GUI Application for Port Scanner"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Port Scanner")
        self.root.geometry("900x750")
        self.root.resizable(False, False)
        
        # Variables
        self.target_var = StringVar()
        self.port_mode_var = StringVar(value="common")
        self.custom_ports_var = StringVar(value="80,443,22,21")
        self.timeout_var = DoubleVar(value=1.0)
        self.threads_var = IntVar(value=100)
        self.scanning = False
        self.scanner = None
        self.scan_results = None
        
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.scanner_frame = Frame(self.notebook, bg='white')
        self.settings_frame = Frame(self.notebook, bg='white')
        self.help_frame = Frame(self.notebook, bg='white')
        
        self.notebook.add(self.scanner_frame, text="  Port Scanner  ")
        self.notebook.add(self.settings_frame, text="  Settings  ")
        self.notebook.add(self.help_frame, text="  Help  ")
        
        # Setup tabs
        self.setup_scanner_tab()
        self.setup_settings_tab()
        self.setup_help_tab()
        
        # Status bar
        self.status_label = Label(root, text="Ready", bg='#ecf0f1',
                                 anchor=W, padx=10, pady=5, font=("Arial", 9))
        self.status_label.pack(fill=X, side=BOTTOM)
    
    def setup_scanner_tab(self):
        """Setup the main scanner interface"""
        # Title
        title = Label(self.scanner_frame, text="🔍 Advanced Port Scanner",
                     font=("Arial", 16, "bold"), bg='white', fg='#2c3e50')
        title.pack(pady=20)
        
        # Description
        desc = Label(self.scanner_frame,
                    text="Scan single IP or entire subnets for open ports",
                    font=("Arial", 10), bg='white', fg='#7f8c8d')
        desc.pack(pady=5)
        
        # Configuration frame
        config_frame = LabelFrame(self.scanner_frame, text="  Scan Configuration  ",
                                 font=("Arial", 11, "bold"), bg='white',
                                 padx=20, pady=15)
        config_frame.pack(padx=20, pady=10, fill=X)
        
        # Target input
        target_label = Label(config_frame, text="Target IP or Range:",
                           font=("Arial", 10), bg='white')
        target_label.grid(row=0, column=0, sticky=W, pady=5)
        
        target_entry = Entry(config_frame, textvariable=self.target_var,
                           width=30, font=("Courier", 10))
        target_entry.grid(row=0, column=1, padx=10, pady=5)
        
        target_hint = Label(config_frame, text="(e.g., 192.168.1.1 or 192.168.1.0/24)",
                          font=("Arial", 8), bg='white', fg='#7f8c8d')
        target_hint.grid(row=0, column=2, sticky=W, padx=5)
        
        # Port selection
        port_label = Label(config_frame, text="Ports to Scan:",
                         font=("Arial", 10), bg='white')
        port_label.grid(row=1, column=0, sticky=W, pady=5)
        
        port_frame = Frame(config_frame, bg='white')
        port_frame.grid(row=1, column=1, columnspan=2, sticky=W, padx=10, pady=5)
        
        Radiobutton(port_frame, text="Common Ports (23 ports)",
                   variable=self.port_mode_var, value="common",
                   bg='white', font=("Arial", 9)).pack(side=LEFT, padx=5)
        
        Radiobutton(port_frame, text="Top 100",
                   variable=self.port_mode_var, value="top100",
                   bg='white', font=("Arial", 9)).pack(side=LEFT, padx=5)
        
        Radiobutton(port_frame, text="Custom",
                   variable=self.port_mode_var, value="custom",
                   bg='white', font=("Arial", 9)).pack(side=LEFT, padx=5)
        
        # Custom ports entry
        custom_ports_entry = Entry(config_frame, textvariable=self.custom_ports_var,
                                  width=30, font=("Courier", 9))
        custom_ports_entry.grid(row=2, column=1, padx=10, pady=5)
        
        custom_hint = Label(config_frame, text="(e.g., 80,443 or 1-1000)",
                          font=("Arial", 8), bg='white', fg='#7f8c8d')
        custom_hint.grid(row=2, column=2, sticky=W, padx=5)
        
        # Buttons frame
        buttons_frame = Frame(self.scanner_frame, bg='white')
        buttons_frame.pack(pady=20)
        
        # Scan button
        self.scan_btn = Button(buttons_frame, text="🚀 Start Scan",
                              command=self.start_scan,
                              bg='#3498db', fg='white',
                              font=("Arial", 12, "bold"),
                              padx=40, pady=12, relief=FLAT,
                              cursor='hand2')
        self.scan_btn.grid(row=0, column=0, padx=10)
        
        # Stop button
        self.stop_btn = Button(buttons_frame, text="⏹ Stop Scan",
                              command=self.stop_scan,
                              bg='#e74c3c', fg='white',
                              font=("Arial", 12, "bold"),
                              padx=40, pady=12, relief=FLAT,
                              cursor='hand2', state=DISABLED)
        self.stop_btn.grid(row=0, column=1, padx=10)
        
        # Export button
        export_btn = Button(buttons_frame, text="💾 Export Reports",
                          command=self.export_reports,
                          bg='#27ae60', fg='white',
                          font=("Arial", 12, "bold"),
                          padx=40, pady=12, relief=FLAT,
                          cursor='hand2')
        export_btn.grid(row=0, column=2, padx=10)
        
        # Results frame
        results_label = Label(self.scanner_frame, text="Scan Results:",
                            font=("Arial", 11, "bold"), bg='white', anchor=W)
        results_label.pack(fill=X, padx=20, pady=(10, 5))
        
        results_frame = Frame(self.scanner_frame, bg='white')
        results_frame.pack(fill=BOTH, expand=True, padx=20, pady=10)
        
        # Scrolled text for results
        self.result_text = scrolledtext.ScrolledText(
            results_frame,
            height=15,
            width=100,
            font=("Courier", 9),
            wrap=WORD,
            relief=SOLID,
            borderwidth=1,
            padx=10,
            pady=10
        )
        self.result_text.pack(fill=BOTH, expand=True)
        
        # Initial message
        welcome_msg = """
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║          Welcome to Advanced Port Scanner!                       ║
║                                                                  ║
║  Configure your scan settings and click 'Start Scan'            ║
║  to begin port scanning.                                        ║
║                                                                  ║
║  ⚠️  Only scan systems you own or have permission to scan!       ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
        """
        self.result_text.insert(1.0, welcome_msg)
        self.result_text.config(state=DISABLED)
    
    def setup_settings_tab(self):
        """Setup the settings interface"""
        # Title
        title = Label(self.settings_frame, text="⚙️ Scan Settings",
                     font=("Arial", 16, "bold"), bg='white', fg='#2c3e50')
        title.pack(pady=20)
        
        # Performance settings
        perf_frame = LabelFrame(self.settings_frame, text="  Performance Settings  ",
                               font=("Arial", 11, "bold"), bg='white',
                               padx=20, pady=15)
        perf_frame.pack(padx=40, pady=20, fill=X)
        
        # Timeout setting
        Label(perf_frame, text="Socket Timeout (seconds):",
              font=("Arial", 10), bg='white').grid(row=0, column=0, sticky=W, pady=10)
        
        timeout_frame = Frame(perf_frame, bg='white')
        timeout_frame.grid(row=0, column=1, sticky=W, padx=10)
        
        Scale(timeout_frame, from_=0.1, to=5.0, resolution=0.1,
             variable=self.timeout_var, orient=HORIZONTAL,
             length=200).pack(side=LEFT)
        
        Label(timeout_frame, textvariable=self.timeout_var,
              font=("Arial", 9, "bold"), bg='white').pack(side=LEFT, padx=10)
        
        # Threads setting
        Label(perf_frame, text="Max Threads:",
              font=("Arial", 10), bg='white').grid(row=1, column=0, sticky=W, pady=10)
        
        threads_frame = Frame(perf_frame, bg='white')
        threads_frame.grid(row=1, column=1, sticky=W, padx=10)
        
        Scale(threads_frame, from_=10, to=500, resolution=10,
             variable=self.threads_var, orient=HORIZONTAL,
             length=200).pack(side=LEFT)
        
        Label(threads_frame, textvariable=self.threads_var,
              font=("Arial", 9, "bold"), bg='white').pack(side=LEFT, padx=10)
        
        # Info
        info_text = """
⚡ Performance Tips:
   • Higher timeout = More accurate but slower
   • More threads = Faster but more resource intensive
   • For local networks: timeout 0.5s, threads 200
   • For internet scans: timeout 2.0s, threads 100
        """
        
        Label(perf_frame, text=info_text, font=("Arial", 9),
              bg='white', fg='#7f8c8d', justify=LEFT).grid(row=2, column=0,
                                                           columnspan=2,
                                                           sticky=W, pady=10)
        
        # Common port categories
        cat_frame = LabelFrame(self.settings_frame, text="  Port Categories  ",
                              font=("Arial", 11, "bold"), bg='white',
                              padx=20, pady=15)
        cat_frame.pack(padx=40, pady=20, fill=BOTH, expand=True)
        
        categories_text = """
🔴 Critical Ports (Remote Access):
   21 (FTP), 22 (SSH), 23 (Telnet), 3389 (RDP), 5900 (VNC)

🌐 Web Ports:
   80 (HTTP), 443 (HTTPS), 8080 (HTTP-Proxy), 8443 (HTTPS-Alt)

💾 Database Ports:
   3306 (MySQL), 5432 (PostgreSQL), 27017 (MongoDB), 
   6379 (Redis), 9200 (Elasticsearch)

📧 Email Ports:
   25 (SMTP), 110 (POP3), 143 (IMAP), 587 (SMTP-Submission)

📁 File Sharing:
   445 (SMB), 139 (NetBIOS), 2049 (NFS)
        """
        
        Label(cat_frame, text=categories_text, font=("Courier", 9),
              bg='white', justify=LEFT).pack(anchor=W)
    
    def setup_help_tab(self):
        """Setup the help interface"""
        # Title
        title = Label(self.help_frame, text="📖 Help & Usage",
                     font=("Arial", 16, "bold"), bg='white', fg='#2c3e50')
        title.pack(pady=20)
        
        # Help content
        help_scroll = scrolledtext.ScrolledText(self.help_frame,
                                               height=25,
                                               width=90,
                                               font=("Courier", 9),
                                               wrap=WORD,
                                               bg='white')
        help_scroll.pack(fill=BOTH, expand=True, padx=20, pady=10)
        
        help_text = """
╔═══════════════════════════════════════════════════════════════╗
║                    ADVANCED PORT SCANNER                       ║
║                         QUICK GUIDE                            ║
╚═══════════════════════════════════════════════════════════════╝

🎯 HOW TO USE:

1. SINGLE HOST SCAN
   • Target: 192.168.1.1
   • Ports: Common Ports
   • Click: Start Scan

2. SUBNET SCAN
   • Target: 192.168.1.0/24
   • Ports: Common Ports
   • Click: Start Scan

3. CUSTOM PORTS
   • Target: 192.168.1.1
   • Ports: Custom → Enter "80,443,22"
   • Click: Start Scan

────────────────────────────────────────────────────────────────

⚠️  LEGAL WARNING:

✅ DO:
   • Scan your own systems
   • Scan with written permission
   • Use for learning (on your network)

❌ DON'T:
   • Scan systems without permission
   • Scan government/military networks
   • Use for malicious purposes

Unauthorized port scanning is ILLEGAL!

────────────────────────────────────────────────────────────────

🔧 SETTINGS:

Socket Timeout:
   • Lower = Faster but may miss services
   • Higher = More accurate but slower
   • Recommended: 1.0-2.0 seconds

Max Threads:
   • More = Faster scanning
   • Too many = May crash
   • Recommended: 100-200 threads

────────────────────────────────────────────────────────────────

📊 RESULTS:

Port States:
   • OPEN - Port accepting connections
   • Banner - Service version info

Common Ports:
   22 = SSH, 80 = HTTP, 443 = HTTPS
   3306 = MySQL, 3389 = RDP

────────────────────────────────────────────────────────────────

💾 EXPORT:

After scanning, click "Export Reports" to save:
   • CSV - Spreadsheet format
   • JSON - Machine-readable
   • HTML - Beautiful web report

────────────────────────────────────────────────────────────────

💡 TIPS:

1. Test on localhost first: 127.0.0.1
2. Start with common ports
3. Increase threads for faster scans
4. Save results for comparison

────────────────────────────────────────────────────────────────

Created by: bnahmedsoumaya00
Project 3 - Cybersecurity Python Roadmap

Happy Scanning! 🚀🔒
        """
        
        help_scroll.insert(1.0, help_text)
        help_scroll.config(state=DISABLED)
    
    def get_ports_to_scan(self):
        """Get list of ports based on selection"""
        mode = self.port_mode_var.get()
        
        if mode == "common":
            return sorted(COMMON_PORTS.keys())
        elif mode == "top100":
            top_ports = list(range(1, 101))
            top_ports.extend([443, 8080, 8443, 3306, 3389, 5432, 27017])
            return sorted(set(top_ports))
        elif mode == "custom":
            return parse_port_range(self.custom_ports_var.get())
        
        return []
    
    def start_scan(self):
        """Start the scanning process"""
        target = self.target_var.get().strip()
        
        if not target:
            messagebox.showwarning("Input Required",
                                 "Please enter a target IP or range!")
            return
        
        if not validate_ip(target):
            messagebox.showerror("Invalid Target",
                               f"'{target}' is not a valid IP address or range!")
            return
        
        ports = self.get_ports_to_scan()
        if not ports:
            messagebox.showwarning("No Ports",
                                 "Please select ports to scan!")
            return
        
        # Confirm large scan
        if '/' in target:
            network = ipaddress.ip_network(target, strict=False)
            total_scans = network.num_addresses * len(ports)
            if total_scans > 10000:
                confirm = messagebox.askyesno(
                    "Large Scan",
                    f"This will perform {total_scans:,} port checks.\n"
                    f"This may take a while. Continue?"
                )
                if not confirm:
                    return
        
        # Update UI
        self.scan_btn.config(state=DISABLED)
        self.stop_btn.config(state=NORMAL)
        self.scanning = True
        
        # Clear results
        self.result_text.config(state=NORMAL)
        self.result_text.delete(1.0, END)
        self.result_text.insert(1.0, "⏳ Initializing scan...\n\n")
        self.result_text.config(state=DISABLED)
        
        # Start scan in separate thread
        scan_thread = threading.Thread(target=self.run_scan,
                                       args=(target, ports))
        scan_thread.daemon = True
        scan_thread.start()
    
    def run_scan(self, target, ports):
        """Run the actual scan"""
        try:
            self.update_status(f"Scanning {target}...")
            
            timeout = self.timeout_var.get()
            threads = self.threads_var.get()
            self.scanner = PortScanner(timeout=timeout, max_threads=threads)
            
            if '/' in target:
                results = self.scanner.scan_range(target, ports)
            else:
                self.scanner.scan_start_time = time.time()
                results = {target: self.scanner.scan_host(target, ports)}
                self.scanner.scan_end_time = time.time()
            
            self.scan_results = results
            duration = self.scanner.get_scan_duration()
            report = ReportGenerator.generate_terminal_report(results, duration)
            
            self.result_text.config(state=NORMAL)
            self.result_text.delete(1.0, END)
            self.result_text.insert(1.0, report)
            self.result_text.config(state=DISABLED)
            
            total_open = sum(len(ports) for ports in results.values())
            self.update_status(f"Scan complete! Found {total_open} open ports")
            
            messagebox.showinfo("Scan Complete",
                              f"Scan finished in {duration:.2f} seconds\n"
                              f"Found {total_open} open ports")
            
        except Exception as e:
            self.result_text.config(state=NORMAL)
            self.result_text.delete(1.0, END)
            self.result_text.insert(1.0, f"❌ Error during scan:\n\n{str(e)}")
            self.result_text.config(state=DISABLED)
            self.update_status("Scan failed!")
            messagebox.showerror("Scan Error", f"An error occurred:\n{str(e)}")
        
        finally:
            self.scan_btn.config(state=NORMAL)
            self.stop_btn.config(state=DISABLED)
            self.scanning = False
    
    def stop_scan(self):
        """Stop the current scan"""
        if self.scanning and self.scanner:
            self.scanner.stop()
            self.scanning = False
            self.update_status("Stopping scan...")
            messagebox.showinfo("Scan Stopped", "Scan has been stopped.")
    
    def export_reports(self):
        """Export scan results to files"""
        if not self.scan_results:
            messagebox.showwarning("No Results",
                                 "Please run a scan first!")
            return
        
        directory = filedialog.askdirectory(title="Select Output Directory")
        if not directory:
            return
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_filename = f"{directory}/scan_{timestamp}"
        
        try:
            duration = self.scanner.get_scan_duration() if self.scanner else 0
            
            ReportGenerator.save_csv_report(self.scan_results,
                                          f"{base_filename}.csv")
            ReportGenerator.save_json_report(self.scan_results, duration,
                                           f"{base_filename}.json")
            ReportGenerator.save_html_report(self.scan_results, duration,
                                           f"{base_filename}.html")
            
            messagebox.showinfo("Export Complete",
                              f"Reports exported successfully!\n\n"
                              f"Location: {directory}\n"
                              f"Formats: CSV, JSON, HTML")
            
        except Exception as e:
            messagebox.showerror("Export Error",
                               f"Failed to export reports:\n{str(e)}")
    
    def update_status(self, message):
        """Update status bar message"""
        self.status_label.config(text=message)
        self.root.update()


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Main function to run the GUI application"""
    root = Tk()
    app = PortScannerGUI(root)
    
    # Center window on screen
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
    root.mainloop()


if __name__ == "__main__":
    main()