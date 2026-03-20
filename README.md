# NMAP SSL Security Scanner

A complete web-based tool to perform advanced SSL/TLS and Port vulnerability scans on a list of IPs and Ports.
Built with Python/Flask, NMAP, and a modern, beautiful Vanilla CSS frontend featuring glassmorphism elements.

## Features
- **Secure Authentication**: Protected dashboard using hashed credentials algorithm.
- **CSV Uploads**: Upload a list of targets and automatically scan them.
- **In-depth NMAP Parsing**: 
  - Detects Service and Version (flags version disclosure).
  - Checks if SSL certificate is expired against the current system date.
  - Checks if SSL certificate issuer is untrusted or self-signed.
  - Flags outdated TLS versions (TLS 1.0, TLS 1.1).
  - Evaluates TLS 1.2/1.3 ciphers and flags weak or deprecated ones.
- **Raw Output Viewer**: Inspect the exact command and raw NMAP output for each scanned target.
- **CSV Export**: Download the findings with a single click.

---

## 🚀 Installation & Setup Guide

### Prerequisites for All Operating Systems
- **Python 3.8+** must be installed.
- **Git** must be installed.
- **NMAP** must be installed in order for the backend to execute scans.

### Mac Setup Instructions
1. **Install Git & Python** (if not already installed):
   - You can download Python from python.org or use Homebrew: `brew install python`
   - Git is usually pre-installed on Mac, or installable via `xcode-select --install`
2. **Install NMAP**:
   - Open your Terminal and run: `brew install nmap`
   - *(If you don't have Homebrew, install it first via [brew.sh](https://brew.sh))*
3. **Clone the Repository**:
   ```bash
   git clone <your-github-repo-url>
   cd nmap_scanner_app
   ```
4. **Set Up a Virtual Environment (Recommended)**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
5. **Install Python Dependencies**:
   ```bash
   pip3 install -r requirements.txt
   ```
6. **Run the Application**:
   ```bash
   python3 app.py
   ```
   *The app will be accessible at http://127.0.0.1:5001*

### Windows Setup Instructions
1. **Install Git & Python**:
   - Download and install Python from [python.org](https://www.python.org/downloads/windows/). **Important:** During installation, check the box that says "Add Python to PATH".
   - Download Git from [git-scm.com](https://git-scm.com/download/win).
2. **Install NMAP**:
   - Download the Windows installer from the [official Nmap site](https://nmap.org/download.html) and run the executable. Nmap will automatically be added to your system PATH.
3. **Clone the Repository**:
   - Open **Command Prompt** or **PowerShell**.
   ```cmd
   git clone <your-github-repo-url>
   cd nmap_scanner_app
   ```
4. **Set Up a Virtual Environment (Recommended)**:
   ```cmd
   python -m venv venv
   venv\Scripts\activate
   ```
5. **Install Python Dependencies**:
   ```cmd
   pip install -r requirements.txt
   ```
6. **Run the Application**:
   ```cmd
   python app.py
   ```
   *The app will be accessible at http://127.0.0.1:5001*

---

## How to use
1. Go to `http://127.0.0.1:5001`.
2. Login using the default credentials.
3. Prepare a target `.csv` file. It **must contain** headers named `IP` and `Port`.
4. Drag and drop the `.csv` file into the upload zone on the web interface.
5. Watch the real-time background scanning complete and click **Download CSV Report** when ready.

---
&copy; Copyright at Vedant Patil
