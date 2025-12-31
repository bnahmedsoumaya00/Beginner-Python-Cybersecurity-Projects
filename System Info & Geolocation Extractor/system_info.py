"""
System Info & Geolocation Extractor
Project 2 - Cybersecurity Python Roadmap
Author: bnahmedsoumaya00
Date: December 30, 2025
"""

import platform
import socket
import uuid
import requests
import json
import os
from datetime import datetime
from tkinter import *
from tkinter import ttk, messagebox, scrolledtext
from getmac import get_mac_address


def get_system_info():
    """Gather comprehensive system information"""
    try:
        info = {
            'Operating System': platform.system(),
            'OS Version': platform.version(),
            'OS Release': platform.release(),
            'Architecture': platform.machine(),
            'Processor': platform.processor(),
            'Hostname': platform.node(),
            'Python Version': platform.python_version(),
        }
        return info
    except Exception as e:
        return {'error': f"Failed to get system info: {str(e)}"}


def get_network_info():
    """Gather network-related information"""
    try:
        hostname = socket.gethostname()
        
        # Get local IP
        try:
            local_ip = socket.gethostbyname(hostname)
        except:
            local_ip = "Unable to determine"
        
        # Get all local IPs
        try:
            all_ips = socket.gethostbyname_ex(hostname)[2]
        except:
            all_ips = [local_ip]
        
        # Get MAC address
        try:
            mac_address = get_mac_address()
            if not mac_address:
                # Fallback to uuid method
                mac_int = uuid.getnode()
                mac_address = ':'.join(['{:02x}'.format((mac_int >> elements) & 0xff) 
                                       for elements in range(0, 48, 8)][::-1]).upper()
        except:
            mac_address = "Unable to determine"
        
        info = {
            'Hostname': hostname,
            'Local IP': local_ip,
            'All Local IPs': ', '.join(all_ips),
            'MAC Address': mac_address,
        }
        return info
    except Exception as e:
        return {'error': f"Failed to get network info: {str(e)}"}


def get_public_ip():
    """Get public IP address using multiple fallback services"""
    services = [
        'https://api.ipify.org?format=json',
        'https://api.my-ip.io/ip.json',
        'https://ipinfo.io/ip',
    ]
    
    for service in services:
        try:
            response = requests.get(service, timeout=5)
            if response.status_code == 200:
                # Handle different response formats
                if 'ipify' in service:
                    return response.json()['ip']
                elif 'my-ip.io' in service:
                    return response.json()['ip']
                else:
                    return response.text.strip()
        except:
            continue
    
    return "Unable to fetch public IP"


def get_geolocation(ip_address, api_token=None):
    """Get geolocation data for an IP address using IPinfo.io API"""
    try:
        url = f"https://ipinfo.io/{ip_address}/json"
        
        # Add token if provided
        params = {}
        if api_token:
            params['token'] = api_token
        
        response = requests.get(url, params=params, timeout=10)
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 429:
            return {'error': 'Rate limit exceeded. Consider adding an API token.'}
        else:
            return {'error': f'API returned status code: {response.status_code}'}
            
    except requests.exceptions.Timeout:
        return {'error': 'Request timed out'}
    except requests.exceptions.RequestException as e:
        return {'error': f'Request failed: {str(e)}'}
    except Exception as e:
        return {'error': f'Unexpected error: {str(e)}'}


def format_geolocation_data(geo_data):
    """Format geolocation data into readable dictionary"""
    if 'error' in geo_data:
        return geo_data
    
    formatted = {
        'IP Address': geo_data.get('ip', 'N/A'),
        'Hostname': geo_data.get('hostname', 'N/A'),
        'City': geo_data.get('city', 'N/A'),
        'Region': geo_data.get('region', 'N/A'),
        'Country': geo_data.get('country', 'N/A'),
        'Country Name': get_country_name(geo_data.get('country', '')),
        'Location': geo_data.get('loc', 'N/A'),
        'Organization': geo_data.get('org', 'N/A'),
        'Postal Code': geo_data.get('postal', 'N/A'),
        'Timezone': geo_data.get('timezone', 'N/A'),
    }
    return formatted


def get_country_name(country_code):
    """Convert country code to full name"""
    countries = {
        'US': 'United States', 'GB': 'United Kingdom', 'CA': 'Canada',
        'AU': 'Australia', 'DE': 'Germany', 'FR': 'France', 'JP': 'Japan',
        'CN': 'China', 'IN': 'India', 'BR': 'Brazil', 'RU': 'Russia',
        'IT': 'Italy', 'ES': 'Spain', 'MX': 'Mexico', 'NL': 'Netherlands',
        'SE': 'Sweden', 'NO': 'Norway', 'DK': 'Denmark', 'FI': 'Finland',
        'PL': 'Poland', 'CH': 'Switzerland', 'BE': 'Belgium', 'AT': 'Austria',
        'TN': 'Tunisia', 'EG': 'Egypt', 'MA': 'Morocco', 'ZA': 'South Africa',
    }
    return countries.get(country_code, country_code)


def save_report_json(data, filename=None):
    """Save gathered information to JSON file"""
    try:
        # Create output directory if it doesn't exist
        output_dir = 'output'
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Generate filename if not provided
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'system_report_{timestamp}.json'
        
        filepath = os.path.join(output_dir, filename)
        
        # Add metadata
        report = {
            'timestamp': datetime.now().isoformat(),
            'report_type': 'System Information & Geolocation Report',
            'data': data
        }
        
        # Save to file
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=4)
        
        return filepath
    except Exception as e:
        raise Exception(f"Failed to save report: {str(e)}")


def generate_terminal_report(data):
    """Generate formatted terminal output"""
    report = []
    report.append("╔" + "═" * 58 + "╗")
    report.append("║" + " " * 10 + "SYSTEM INFORMATION REPORT" + " " * 23 + "║")
    report.append("╚" + "═" * 58 + "╝")
    report.append("")
    
    # System Information
    if 'system_info' in data and 'error' not in data['system_info']:
        report.append("🖥️  SYSTEM INFORMATION:")
        report.append("─" * 60)
        for key, value in data['system_info'].items():
            report.append(f"   {key:20}: {value}")
        report.append("")
    
    # Network Information
    if 'network_info' in data and 'error' not in data['network_info']:
        report.append("🌐 NETWORK INFORMATION:")
        report.append("─" * 60)
        for key, value in data['network_info'].items():
            report.append(f"   {key:20}: {value}")
        report.append("")
    
    # Public IP
    if 'public_ip' in data:
        report.append("🌍 PUBLIC IP ADDRESS:")
        report.append("─" * 60)
        report.append(f"   IP Address          : {data['public_ip']}")
        report.append("")
    
    # Geolocation
    if 'geolocation' in data:
        geo = data['geolocation']
        if 'error' in geo:
            report.append("📍 GEOLOCATION:")
            report.append("─" * 60)
            report.append(f"   Error: {geo['error']}")
            report.append("")
        else:
            report.append("📍 GEOLOCATION DATA:")
            report.append("─" * 60)
            for key, value in geo.items():
                if value != 'N/A':
                    report.append(f"   {key:20}: {value}")
            report.append("")
    
    # Security Notice
    report.append("⚠️  SECURITY NOTICE:")
    report.append("─" * 60)
    report.append("   This information can be used for system fingerprinting.")
    report.append("   Be cautious about sharing this data publicly.")
    report.append("   MAC addresses and local IPs should remain private.")
    report.append("")
    report.append("═" * 60)
    
    return "\n".join(report)


class SystemInfoApp:
    """Main application class for System Info Extractor"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("System Info & Geolocation Extractor")
        self.root.geometry("800x700")
        self.root.resizable(False, False)
        
        # Variables
        self.api_token = StringVar()
        self.gathered_data = None
        
        # Load saved API token if exists
        self.load_api_token()
        
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.scanner_frame = Frame(self.notebook, bg='white')
        self.settings_frame = Frame(self.notebook, bg='white')
        
        self.notebook.add(self.scanner_frame, text="  System Scanner  ")
        self.notebook.add(self.settings_frame, text="  Settings  ")
        
        # Setup tabs
        self.setup_scanner_tab()
        self.setup_settings_tab()
    
    def setup_scanner_tab(self):
        """Setup the main scanner interface"""
        # Title
        title = Label(self.scanner_frame, text="🔍 System Information Scanner",
                     font=("Arial", 16, "bold"), bg='white', fg='#2c3e50')
        title.pack(pady=20)
        
        # Description
        desc = Label(self.scanner_frame,
                    text="Gather system information, network details, and geolocation data",
                    font=("Arial", 10), bg='white', fg='#7f8c8d')
        desc.pack(pady=5)
        
        # Buttons frame
        buttons_frame = Frame(self.scanner_frame, bg='white')
        buttons_frame.pack(pady=20)
        
        # Scan button
        scan_btn = Button(buttons_frame, text="🚀 Run Full Scan",
                         command=self.run_full_scan,
                         bg='#3498db', fg='white',
                         font=("Arial", 12, "bold"),
                         padx=40, pady=12, relief=FLAT,
                         cursor='hand2')
        scan_btn.grid(row=0, column=0, padx=10)
        
        # Save button
        save_btn = Button(buttons_frame, text="💾 Save Report (JSON)",
                         command=self.save_report,
                         bg='#27ae60', fg='white',
                         font=("Arial", 12, "bold"),
                         padx=40, pady=12, relief=FLAT,
                         cursor='hand2')
        save_btn.grid(row=0, column=1, padx=10)
        
        # Clear button
        clear_btn = Button(buttons_frame, text="🗑️ Clear Output",
                          command=self.clear_output,
                          bg='#e74c3c', fg='white',
                          font=("Arial", 12, "bold"),
                          padx=40, pady=12, relief=FLAT,
                          cursor='hand2')
        clear_btn.grid(row=0, column=2, padx=10)
        
        # Results frame
        results_label = Label(self.scanner_frame, text="Scan Results:",
                             font=("Arial", 11, "bold"), bg='white', anchor=W)
        results_label.pack(fill=X, padx=20, pady=(10, 5))
        
        results_frame = Frame(self.scanner_frame, bg='white')
        results_frame.pack(fill=BOTH, expand=True, padx=20, pady=10)
        
        # Scrolled text for results
        self.result_text = scrolledtext.ScrolledText(
            results_frame,
            height=25,
            width=90,
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
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║     Welcome to System Info & Geolocation Extractor!     ║
║                                                          ║
║  Click 'Run Full Scan' to gather system information     ║
║  and geolocation data.                                  ║
║                                                          ║
║  ⚠️  Privacy Notice:                                     ║
║  This tool collects sensitive system information.       ║
║  Be careful when sharing the generated reports.         ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
        """
        self.result_text.insert(1.0, welcome_msg)
        self.result_text.config(state=DISABLED)
        
        # Status bar
        self.status_label = Label(self.scanner_frame, text="Ready",
                                 font=("Arial", 9), bg='#ecf0f1',
                                 anchor=W, padx=10, pady=5)
        self.status_label.pack(fill=X, side=BOTTOM)
    
    def setup_settings_tab(self):
        """Setup the settings interface"""
        # Title
        title = Label(self.settings_frame, text="⚙️ Settings",
                     font=("Arial", 16, "bold"), bg='white', fg='#2c3e50')
        title.pack(pady=20)
        
        # API Settings
        api_frame = LabelFrame(self.settings_frame, text="  API Configuration  ",
                              font=("Arial", 11, "bold"), bg='white',
                              padx=20, pady=15)
        api_frame.pack(padx=40, pady=20, fill=X)
        
        Label(api_frame, text="IPinfo.io API Token (Optional):",
              font=("Arial", 10), bg='white').pack(anchor=W, pady=(5, 2))
        
        token_entry = Entry(api_frame, textvariable=self.api_token,
                           width=50, font=("Courier", 10))
        token_entry.pack(pady=5, ipady=3)
        
        Label(api_frame,
              text="Get your free API token at: https://ipinfo.io/signup",
              font=("Arial", 9), bg='white', fg='#3498db',
              cursor='hand2').pack(anchor=W, pady=(2, 5))
        
        Label(api_frame,
              text="Free tier: 50,000 requests/month\nWithout token: Rate limited to ~1000 requests/day",
              font=("Arial", 9), bg='white', fg='#7f8c8d').pack(anchor=W)
        
        # Save button
        save_token_btn = Button(api_frame, text="💾 Save Token",
                               command=self.save_api_token,
                               bg='#27ae60', fg='white',
                               font=("Arial", 10, "bold"),
                               padx=20, pady=8, relief=FLAT,
                               cursor='hand2')
        save_token_btn.pack(pady=10)
        
        # Information section
        info_frame = LabelFrame(self.settings_frame, text="  About This Tool  ",
                               font=("Arial", 11, "bold"), bg='white',
                               padx=20, pady=15)
        info_frame.pack(padx=40, pady=20, fill=BOTH, expand=True)
        
        info_text = """
📋 What This Tool Does:
   • Gathers comprehensive system information (OS, architecture, etc.)
   • Retrieves network details (hostname, IPs, MAC address)
   • Fetches your public IP address
   • Performs geolocation lookup based on your IP
   • Generates formatted reports (terminal + JSON export)

🔒 Security & Privacy:
   • All data stays on your machine (no external storage)
   • MAC addresses and local IPs are sensitive - don't share
   • Public IP reveals your approximate location
   • This tool demonstrates OSINT (Open Source Intelligence) techniques

⚠️  Ethical Use:
   • Only scan systems you own or have permission to scan
   • Understand information disclosure risks
   • Use for educational and security awareness purposes

📚 Learn More:
   • OSINT: Open Source Intelligence gathering
   • Footprinting: Information gathering phase of security assessment
   • Reconnaissance: Systematic discovery of target information
        """
        
        info_label = Label(info_frame, text=info_text,
                          font=("Arial", 9), bg='white',
                          justify=LEFT, anchor=W)
        info_label.pack(fill=BOTH, expand=True)
        
        # Credits
        credits = Label(self.settings_frame,
                       text="Created by: bnahmedsoumaya00 | Project 2 - Cybersecurity Python Roadmap",
                       font=("Arial", 8), bg='white', fg='#95a5a6')
        credits.pack(side=BOTTOM, pady=10)
    
    def run_full_scan(self):
        """Execute full system scan"""
        self.update_status("Scanning system...")
        self.result_text.config(state=NORMAL)
        self.result_text.delete(1.0, END)
        self.result_text.insert(1.0, "⏳ Gathering information...\n\n")
        self.result_text.config(state=DISABLED)
        self.root.update()
        
        try:
            # Gather all information
            data = {}
            
            # System info
            self.update_status("Gathering system information...")
            data['system_info'] = get_system_info()
            
            # Network info
            self.update_status("Gathering network information...")
            data['network_info'] = get_network_info()
            
            # Public IP
            self.update_status("Fetching public IP address...")
            data['public_ip'] = get_public_ip()
            
            # Geolocation
            if data['public_ip'] != "Unable to fetch public IP":
                self.update_status("Performing geolocation lookup...")
                token = self.api_token.get().strip() or None
                geo_data = get_geolocation(data['public_ip'], token)
                data['geolocation'] = format_geolocation_data(geo_data)
            else:
                data['geolocation'] = {'error': 'Could not fetch public IP'}
            
            # Store data
            self.gathered_data = data
            
            # Generate and display report
            report = generate_terminal_report(data)
            self.result_text.config(state=NORMAL)
            self.result_text.delete(1.0, END)
            self.result_text.insert(1.0, report)
            self.result_text.config(state=DISABLED)
            
            self.update_status("Scan completed successfully!")
            
        except Exception as e:
            self.result_text.config(state=NORMAL)
            self.result_text.delete(1.0, END)
            self.result_text.insert(1.0, f"❌ Error during scan:\n\n{str(e)}")
            self.result_text.config(state=DISABLED)
            self.update_status("Scan failed!")
            messagebox.showerror("Scan Error", f"An error occurred:\n{str(e)}")
    
    def save_report(self):
        """Save the gathered data to JSON file"""
        if not self.gathered_data:
            messagebox.showwarning("No Data",
                                  "Please run a scan first before saving!")
            return
        
        try:
            filepath = save_report_json(self.gathered_data)
            messagebox.showinfo("Success",
                              f"Report saved successfully!\n\nLocation: {filepath}")
            self.update_status(f"Report saved: {filepath}")
        except Exception as e:
            messagebox.showerror("Save Error",
                               f"Failed to save report:\n{str(e)}")
    
    def clear_output(self):
        """Clear the output display"""
        self.result_text.config(state=NORMAL)
        self.result_text.delete(1.0, END)
        welcome_msg = """
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║     Welcome to System Info & Geolocation Extractor!     ║
║                                                          ║
║  Click 'Run Full Scan' to gather system information     ║
║  and geolocation data.                                  ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
        """
        self.result_text.insert(1.0, welcome_msg)
        self.result_text.config(state=DISABLED)
        self.gathered_data = None
        self.update_status("Ready")
    
    def update_status(self, message):
        """Update status bar message"""
        self.status_label.config(text=message)
        self.root.update()
    
    def save_api_token(self):
        """Save API token to config file"""
        try:
            token = self.api_token.get().strip()
            config = {'ipinfo_token': token}
            
            with open('config.json', 'w') as f:
                json.dump(config, f, indent=4)
            
            messagebox.showinfo("Success", "API token saved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save token:\n{str(e)}")
    
    def load_api_token(self):
        """Load API token from config file"""
        try:
            if os.path.exists('config.json'):
                with open('config.json', 'r') as f:
                    config = json.load(f)
                    token = config.get('ipinfo_token', '')
                    self.api_token.set(token)
        except:
            pass  # Ignore if config doesn't exist


def main():
    """Main function to run the application"""
    root = Tk()
    app = SystemInfoApp(root)
    
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