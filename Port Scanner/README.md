# 🔍 Advanced Port Scanner

[![Download v1.0.0](https://img.shields.io/badge/Download-v1.0.0-brightgreen?style=flat-square)](https://github.com/bnahmedsoumaya00/Beginner-Python-Cybersecurity-Projects/releases/download/v1.0.0/port_scanner.exe)
[![Release](https://img.shields.io/github/v/release/bnahmedsoumaya00/Beginner-Python-Cybersecurity-Projects?style=flat-square)](https://github.com/bnahmedsoumaya00/Beginner-Python-Cybersecurity-Projects/releases)

A fast, multithreaded port scanner with both command-line and GUI interfaces. This tool is designed for cybersecurity professionals and enthusiasts to quickly identify open ports, detect services, and generate detailed reports.

---

## 📥 Quick Download (Windows)

**[⬇️ Download port_scanner.exe](https://github.com/bnahmedsoumaya00/Beginner-Python-Cybersecurity-Projects/releases/download/v1.0.0/port_scanner.exe)**

_No install, just double-click. If Windows Defender warns, click "More info" → "Run anyway."_'

---

## ⚙️ Installation

### **Option 1: Windows Executable**
1. Download the EXE file from the [Releases](https://github.com/bnahmedsoumaya00/Beginner-Python-Cybersecurity-Projects/releases).
2. Double-click to run.

### **Option 2: Run from Source (Cross-Platform)**
```bash
git clone https://github.com/bnahmedsoumaya00/Beginner-Python-Cybersecurity-Projects.git
cd "cybersecurity-projects/Port Scanner"
python -m venv venv
venv\Scripts\activate    # or source venv/bin/activate on Mac/Linux
pip install -r requirements.txt
python port_scanner.py
```

---

## 🚦 Features

- **Multithreaded Scanning:** Scan multiple ports simultaneously for faster results.
- **Service Detection:** Identify running services like SSH, HTTP, MySQL, and more.
- **Banner Grabbing:** Retrieve service versions for better vulnerability assessment.
- **Report Generation:** Export results in CSV, JSON, and HTML formats.
- **GUI and CLI:** Choose between an easy-to-use graphical interface or a powerful command-line tool.

---

## 🎯 Usage Examples

### **Command-Line Scanning**
- Scan a single host:
  ```bash
  port_scanner.exe -t 192.168.1.1 -p common
  ```
- Scan specific ports:
  ```bash
  port_scanner.exe -t 192.168.1.1 -p 80,443,22
  ```
- Scan a subnet:
  ```bash
  port_scanner.exe -t 192.168.1.0/24 -p common
  ```

### **GUI Scanning**
1. Launch the GUI by double-clicking `port_scanner_gui.exe`.
2. Enter the target IP or subnet.
3. Select the ports to scan (common, top 100, or custom).
4. Click "Start Scan" and view results in real-time.

---

## 🔒 Security & Privacy

- **Local Data Only:** All scan results are stored locally; no data is uploaded.
- **Ethical Use:** Only scan systems you own or have explicit permission to scan.
- **Legal Compliance:** Unauthorized scanning is illegal and may result in penalties.

---

## 🛠️ Troubleshooting

- **Permission Denied:** Run as Administrator on Windows or use `sudo` on Linux/Mac.
- **Slow Scans:** Increase threads (`--threads 200`) or lower timeout (`--timeout 0.5`).
- **No Results:** Ensure the target is online and not blocking scans.

---

## 👤 Author

Created by: bnahmedsoumaya00  
Project 3 - Cybersecurity Python Roadmap  
December 31, 2025

---

## 📚 Learn More

- **What is Port Scanning?** Port scanning is a method to discover which network ports are open on a device. Each port can run a different service (like a web server on port 80).
- **Why Scan Ports?** To identify vulnerabilities, map networks, and troubleshoot services.
- **How Does It Work?** The scanner attempts to connect to each port. If the connection succeeds, the port is open. This is called a "TCP Connect Scan."

---

## ⚖️ Disclaimer

**READ CAREFULLY:**

This tool is provided for **EDUCATIONAL PURPOSES ONLY**.

By using this tool, you agree to:
- Use it legally and ethically
- Only scan systems you own or have permission to scan
- Accept all responsibility for your actions
- Comply with all applicable laws

The author is **NOT responsible** for:
- Misuse of this tool
- Illegal activities
- Damage caused by this tool
- Legal consequences of unauthorized scanning

**UNAUTHORIZED PORT SCANNING IS ILLEGAL.**