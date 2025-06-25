# WayLoot v3.0 - Advanced Bug Bounty & Penetration Testing Tool

**Developed by Hamza Iqbal** 🏆

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
\`\`\`bash
pip install requests tqdm colorama
\`\`\`

## 🛠️ Installation

1. **Save the script:**
   \`\`\`bash
   # Save wayloot.py to your desired directory
   \`\`\`

2. **Install Python dependencies:**
   \`\`\`bash
   pip install requests tqdm colorama
   \`\`\`

3. **Install Go tools:**
   \`\`\`bash
   go install github.com/lc/gau/v2/cmd/gau@latest
   go install github.com/tomnomnom/waybackurls@latest
   \`\`\`

4. **Verify installation:**
   \`\`\`bash
   gau -h
   waybackurls -h
   \`\`\`

## 🎮 Usage

### Interactive Mode (Recommended)
\`\`\`bash
python wayloot.py
\`\`\`

This launches the beautiful interactive interface where you can:
- View the stunning ASCII art header with developer credits
- Enter your target domain with styled prompts
- Configure Discord webhook with guided setup
- Choose specific features from the color-coded menu
- View real-time progress with beautiful status boxes

### Command Line Mode (Legacy)
\`\`\`bash
python wayloot.py --domain example.com --webhook-url "https://discord.com/api/webhooks/..."
\`\`\`

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

## 📁 Output Structure

\`\`\`
data/
└── example.com/
    ├── urls.txt                    # All discovered URLs
    ├── snapshots.txt               # Snapshot metadata
    ├── snapshots_detailed.txt      # Detailed snapshot info
    ├── secrets.txt                 # Discovered secrets (with dev credits)
    ├── params.txt                  # Extracted parameters
    ├── api_endpoints.txt           # API endpoints
    ├── vulnerabilities.txt         # Potential vulnerabilities (with dev credits)
    ├── live_hosts.txt              # Active hosts (with dev credits)
    ├── state.json                  # Resume state
    ├── js_findings/                # JavaScript files
    │   ├── 20230101_script.js
    │   └── live_app.js
    ├── sensitive_files/            # Sensitive files
    │   ├── 20230101_config.json
    │   └── 20230201_backup.sql
    ├── archive_snapshots/          # All snapshots
    │   └── example.com_login/
    │       ├── 20230101_200.html
    │       └── 20230201_404.html
    └── wordlists/                  # Generated wordlists
        └── paths.txt
\`\`\`

## 🎨 UI Features

### Beautiful Status Messages
- ✅ **Success Messages**: Green colored with checkmark icons
- ❌ **Error Messages**: Red colored with X icons
- ⚠️ **Warning Messages**: Yellow colored with warning icons
- ℹ️ **Info Messages**: Blue colored with info icons
- ⏳ **Loading Messages**: Yellow colored with hourglass icons

### Statistics Tables
Beautiful ASCII tables showing:
- Scan progress and results
- File counts and discoveries
- Performance metrics
- Success rates

### Progress Bars
Custom styled progress bars with:
- Emoji indicators for different scan types
- Real-time progress updates
- Estimated time remaining
- Color-coded completion status

## 🌐 Discord Integration Setup

1. **Create Webhook:**
   - Go to Discord Server Settings → Integrations → Webhooks
   - Click "New Webhook"
   - Name it "WayLoot by Hamza Iqbal" and select a channel
   - Copy the webhook URL

2. **Configure in WayLoot:**
   - Use option [10] in the interactive menu
   - Follow the beautifully styled setup guide
   - Test the connection with automatic verification

3. **Notification Types:**
   - 🔍 Scan progress updates with developer credits
   - 💎 Sensitive file discoveries
   - 🔐 Secret detections
   - ⚠️ Vulnerability findings
   - 🌐 Live host discoveries
   - 📊 Final scan reports with statistics

## 🏆 Developer Recognition

Every output file, Discord notification, and report includes proper developer credits:

- **File Headers**: All generated files include "Developed by Hamza Iqbal"
- **Discord Footers**: All webhook messages show "WayLoot v3.0 by Hamza Iqbal"
- **Terminal Output**: Beautiful ASCII art header with developer credits
- **User Agent**: HTTP requests identify as "WayLoot/3.0 (Advanced Bug Bounty Tool by Hamza Iqbal)"

## ⚡ Performance Tips

### For Large Targets:
- Use option [1] first to assess scope with beautiful progress tracking
- Run specific features based on initial findings
- Use resume functionality for long scans

### For Quick Recon:
- Option [1]: Basic URL gathering with instant feedback
- Option [6]: Live host detection with real-time results
- Option [7]: Sensitive file hunting with progress bars

### For Deep Analysis:
- Option [9]: Full advanced scan with comprehensive reporting
- Enable Discord notifications for real-time updates
- Monitor progress with beautiful statistics tables

## 🚨 Legal Disclaimer

This tool is intended for:
- **Authorized security testing**
- **Bug bounty programs**
- **Educational purposes**
- **Your own assets**

**Unauthorized scanning is illegal.** Users are responsible for compliance with applicable laws and terms of service.

## 🙏 Acknowledgments

**WayLoot v3.0** is built with ❤️ by **Hamza Iqbal** for the ethical hacking community.

Special thanks to:
- **Wayback Machine API** for historical data access
- **@tomnomnom & @lc** for the amazing gau & waybackurls tools
- **Bug bounty community** for inspiration and feedback
- **Security researchers** worldwide for their dedication

## 🔄 Updates & Roadmap

### Planned Features:
- Integration with additional recon APIs
- Machine learning-based vulnerability detection
- Custom pattern configuration
- Export formats (JSON, CSV, XML)
- Integration with popular security tools
- Even more beautiful UI enhancements

### Contributing:
- Report bugs and feature requests
- Submit pull requests
- Share detection patterns
- Improve documentation
- Suggest UI improvements

---

**WayLoot v3.0** - Proudly developed by **Hamza Iqbal** 🏆  
Making bug bounty reconnaissance more efficient, comprehensive, and beautiful! 🎯

*"Empowering ethical hackers with advanced tools and beautiful interfaces"* - Hamza Iqbal
