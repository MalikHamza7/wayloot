# WayLoot 



WayLoot v3.0 is a comprehensive, feature-rich tool designed for bug bounty hunters and penetration testers. It automates the process of gathering, analyzing, and discovering security-relevant information from the Wayback Machine and live targets with a beautiful, intuitive interface.

## 🎨 Beautiful Terminal UI

WayLoot v3.0 features a completely redesigned terminal interface with:
- **Stunning ASCII Art Header** with developer credits
- **Color-coded Status Messages** for better readability
- **Beautiful Menu System** with organized feature boxes
- **Progress Bars** with custom styling
- **Statistics Tables** for comprehensive reporting
- **Professional Footer** with acknowledgments

## 👨‍💻 Developer Credits

**WayLoot v3.0** is proudly developed by **Hamza Iqbal**, a passionate security researcher and bug bounty hunter dedicated to creating tools that empower the ethical hacking community.

### 🏆 About the Developer
- **Name:** Hamza Iqbal
- **Specialization:** Bug Bounty Hunting & Penetration Testing
- **Mission:** Empowering security researchers with advanced reconnaissance tools
- **Year:** 2024

## 🚀 New Features in v3.0

### 🎯 Enhanced User Interface
- **Beautiful ASCII Art Banner** with developer credits
- **Interactive Menu System** with color-coded options
- **Status Boxes** for clear feedback
- **Statistics Tables** for comprehensive reporting
- **Professional Styling** throughout the application

### 🧠 Advanced Analysis Capabilities
- **JavaScript Analysis**: Extract and analyze JS files for secrets and API endpoints
- **Secret Detection**: Advanced regex patterns for API keys, tokens, passwords
- **Vulnerability Scanning**: Detect potential XSS, SQLi, LFI, and other vulnerabilities
- **Parameter Discovery**: Extract all GET/POST parameters for further testing
- **Live Host Detection**: Identify active subdomains and services
- **Wordlist Generation**: Auto-generate custom wordlists from discovered paths

### 🔄 Smart Resume Functionality
- State management with JSON-based persistence
- Resume interrupted scans without losing progress
- Skip already processed URLs and snapshots

### 🌐 Enhanced Discord Integration
- Real-time notifications for all discoveries
- File uploads for reports and wordlists
- Detailed embeds with color-coded severity levels
- Rate limiting to prevent webhook abuse
- Developer credits in all notifications

## 📋 Prerequisites

### Required Tools
1. **Python 3.7+**
2. **Go** (for installing required tools)
3. **gau** (GetAllUrls): `go install github.com/lc/gau/v2/cmd/gau@latest`
4. **waybackurls**: `go install github.com/tomnomnom/waybackurls@latest`

### Python Dependencies
```bash
pip install requests tqdm colorama
```

## 🛠️ Installation

1. **Save the script:**
   ```bash
   # Save wayloot.py to your desired directory
   ```

2. **Install Python dependencies:**
   ```bash
   pip install requests tqdm colorama
   ```

3. **Install Go tools:**
   ```bash
   go install github.com/lc/gau/v2/cmd/gau@latest
   go install github.com/tomnomnom/waybackurls@latest
   ```

4. **Verify installation:**
   ```bash
   gau -h
   waybackurls -h
   ```

## 🎮 Usage

### Interactive Mode (Recommended)
```bash
python wayloot.py
```

This launches the beautiful interactive interface where you can:
- View the stunning ASCII art header with developer credits
- Enter your target domain with styled prompts
- Configure Discord webhook with guided setup
- Choose specific features from the color-coded menu
- View real-time progress with beautiful status boxes

### Command Line Mode (Legacy)
```bash
python wayloot.py --domain example.com --webhook-url "https://discord.com/api/webhooks/..."
```

## 🎯 Feature Menu Options

The interactive menu presents 10 beautifully styled options:

### [1] 🔍 Basic URL Gathering & Snapshot Collection
- Gather URLs using gau and waybackurls
- Collect snapshot metadata from CDX API
- Generate basic reports with statistics tables

### [2] 📊 Comprehensive Snapshot Analysis
- Download ALL available snapshots
- Organize by URL structure and timestamp
- Analyze content for secrets and vulnerabilities

### [3] 🧠 JavaScript Analysis & Endpoint Discovery
- Extract and download JavaScript files
- Discover API endpoints and routes
- Find hardcoded secrets in JS code

### [4] 🔐 Secret Detection & Vulnerability Scanning
- Scan for API keys, tokens, passwords
- Detect potential vulnerabilities (XSS, SQLi, LFI, etc.)
- Generate detailed security reports

### [5] 📂 Parameter Discovery & Wordlist Generation
- Extract all GET/POST parameters
- Generate custom wordlists for fuzzing
- Create path-based wordlists for directory discovery

### [6] 🌐 Live Host Detection & Service Discovery
- Test subdomains for live services
- Identify HTTP/HTTPS availability
- Generate live host reports with statistics

### [7] 💎 Sensitive File Hunter (Advanced)
- Hunt for sensitive file extensions
- Download all historical versions
- Organize by file type and timestamp

### [8] 🔄 Resume Previous Scan
- Continue interrupted scans
- Skip already processed data
- Maintain scan state across sessions

### [9] 🚀 Full Advanced Scan (All Features)
- Run all features in sequence
- Comprehensive reconnaissance
- Generate complete security assessment

### [10] ⚙️ Configure Discord Webhook
- Set up real-time notifications
- Test webhook connectivity
- Configure notification preferences
---

**WayLoot v3.0** - 

![image](https://github.com/user-attachments/assets/2044f482-3313-4b03-978e-132f002db00f)

![image](https://github.com/user-attachments/assets/864f251f-146a-4d68-b41c-438ba4f22f02)

![image](https://github.com/user-attachments/assets/1b5c96f7-660e-4df7-ac51-ac6b7a0c1725)



