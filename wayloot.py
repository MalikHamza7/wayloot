import os
import sys
import subprocess
import argparse
import requests
import json
import time
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote, unquote, urlparse, parse_qs
from tqdm import tqdm
from colorama import init, Fore, Style
import socket
from pathlib import Path

# Initialize colorama
init(autoreset=True)

# --- Constants ---
SENSITIVE_EXTENSIONS = [
    '.pdf', '.xml', '.xls', '.xlsx', '.doc', '.docx', '.zip', '.rar', '.tar', '.gz',
    '.sql', '.bak', '.log', '.db', '.conf', '.env', '.7z', '.backup', '.yml', '.yaml',
    '.json', '.pem', '.key', '.p12', '.pfx', '.cer', '.crt', '.ini', '.cfg', '.txt',
    '.csv', '.config', '.properties', '.old', '.orig', '.temp', '.tmp', '.swp'
]

JS_EXTENSIONS = ['.js', '.jsx', '.ts', '.tsx']
CDX_API_URL = "https://web.archive.org/cdx/search/cdx"
WAYBACK_BASE_URL = "https://web.archive.org/web/"
USER_AGENT = "WayLoot/3.0 (Advanced Bug Bounty Tool by Hamza Iqbal)"

# Secret patterns for detection
SECRET_PATTERNS = {
    'api_key': r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?',
    'aws_access_key': r'AKIA[0-9A-Z]{16}',
    'aws_secret_key': r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?',
    'github_token': r'ghp_[a-zA-Z0-9]{36}',
    'jwt_token': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
    'private_key': r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
    'password': r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?([^"\'\s]{6,})["\']?',
    'token': r'(?i)token\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?',
    'secret': r'(?i)secret\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?',
    'database_url': r'(?i)(database_url|db_url)\s*[:=]\s*["\']?(.*?)["\']?',
    'slack_token': r'xox[baprs]-[0-9a-zA-Z\-]+',
    'discord_token': r'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}',
}

# API endpoint patterns
API_PATTERNS = [
    r'/api/[^"\s<>]+',
    r'/v\d+/[^"\s<>]+',
    r'/rest/[^"\s<>]+',
    r'/graphql[^"\s<>]*',
    r'/webhook[^"\s<>]*',
    r'\.json[^"\s<>]*',
    r'\.xml[^"\s<>]*',
]

# Vulnerability patterns
VULN_PATTERNS = {
    'open_redirect': r'(?i)(redirect|url|next|return|continue)\s*=\s*["\']?(https?://|//)',
    'xss_reflected': r'(?i)(q|search|query|input|data)\s*=\s*["\']?[^"\'&\s]*[<>]',
    'sql_injection': r'(?i)(id|user|page|cat|file|class|url|news)\s*=\s*["\']?\d+["\']?',
    'lfi_rfi': r'(?i)(file|page|include|path|dir)\s*=\s*["\']?[^"\'&\s]*\.\.',
    'exposed_git': r'\.git/(config|HEAD|index)',
    'exposed_env': r'\.env(\.|$)',
    'backup_files': r'\.(bak|backup|old|orig|tmp)$',
}

# --- UI Components ---
def print_header():
    """Print beautiful header with developer credits"""
    header = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  {Fore.WHITE}{Style.BRIGHT}██╗    ██╗ █████╗ ██╗   ██╗██╗      ██████╗  ██████╗ ████████╗{Fore.CYAN}              ║
║  {Fore.WHITE}{Style.BRIGHT}██║    ██║██╔══██╗╚██╗ ██╔╝██║     ██╔═══██╗██╔═══██╗╚══██╔══╝{Fore.CYAN}              ║
║  {Fore.WHITE}{Style.BRIGHT}██║ █╗ ██║███████║ ╚████╔╝ ██║     ██║   ██║██║   ██║   ██║{Fore.CYAN}                 ║
║  {Fore.WHITE}{Style.BRIGHT}██║███╗██║██╔══██║  ╚██╔╝  ██║     ██║   ██║██║   ██║   ██║{Fore.CYAN}                 ║
║  {Fore.WHITE}{Style.BRIGHT}╚███╔███╔╝██║  ██║   ██║   ███████╗╚██████╔╝╚██████╔╝   ██║{Fore.CYAN}                 ║
║  {Fore.WHITE}{Style.BRIGHT} ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝  ╚═════╝    ╚═╝{Fore.CYAN}                 ║
║                                                                              ║
║  {Fore.YELLOW}{Style.BRIGHT}🎯 Advanced Bug Bounty & Penetration Testing Tool v3.0{Fore.CYAN}                   ║
║  {Fore.GREEN}{Style.BRIGHT}🔍 Wayback Machine Intelligence • 🧠 AI-Powered Analysis{Fore.CYAN}                   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.MAGENTA}┌─────────────────────────────────────────────────────────────────────────────┐
│                           {Fore.WHITE}{Style.BRIGHT}🏆 DEVELOPER CREDITS 🏆{Fore.MAGENTA}                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  {Fore.CYAN}{Style.BRIGHT}👨‍💻 Developed By:{Style.RESET_ALL} {Fore.WHITE}{Style.BRIGHT}Hamza Iqbal{Fore.MAGENTA}                                        │
│  {Fore.CYAN}{Style.BRIGHT}🚀 Version:{Style.RESET_ALL} {Fore.YELLOW}3.0 Advanced Edition{Fore.MAGENTA}                                    │
│  {Fore.CYAN}{Style.BRIGHT}📅 Year:{Style.RESET_ALL} {Fore.GREEN}2025{Fore.MAGENTA}                                                        │
│  {Fore.CYAN}{Style.BRIGHT}🎯 Purpose:{Style.RESET_ALL} {Fore.WHITE}Bug Bounty & Penetration Testing{Fore.MAGENTA}                         │
│  {Fore.CYAN}{Style.BRIGHT}⚡ Features:{Style.RESET_ALL} {Fore.YELLOW}10+ Advanced Reconnaissance Modules{Fore.MAGENTA}                     │
│                                                                             │
│  {Fore.RED}{Style.BRIGHT}💝 Special Thanks to the Bug Bounty Community{Fore.MAGENTA}                             │
│  {Fore.GREEN}{Style.BRIGHT}🌟 Built with ❤️  for Ethical Hackers & Security Researchers{Fore.MAGENTA}           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}
"""
    print(header)

def print_separator(char="═", length=80, color=Fore.CYAN):
    """Print a beautiful separator line"""
    print(f"{color}{char * length}{Style.RESET_ALL}")

def print_section_header(title, icon="🎯"):
    """Print a section header with styling"""
    print(f"\n{Fore.CYAN}╔{'═' * (len(title) + 6)}╗")
    print(f"║ {icon} {Fore.WHITE}{Style.BRIGHT}{title}{Fore.CYAN} ║")
    print(f"╚{'═' * (len(title) + 6)}╝{Style.RESET_ALL}")

def print_feature_box(number, icon, title, description, color=Fore.GREEN):
    """Print a feature option in a beautiful box"""
    print(f"{color}┌─────────────────────────────────────────────────────────────────────────────┐")
    print(f"│ {Fore.WHITE}{Style.BRIGHT}[{number}]{color} {icon} {Fore.WHITE}{Style.BRIGHT}{title:<65}{color} │")
    print(f"│     {Fore.CYAN}{description:<69}{color} │")
    print(f"└─────────────────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}")

def print_status_box(status, message, color=Fore.GREEN):
    """Print status message in a box"""
    icon_map = {
        'success': '✅',
        'error': '❌',
        'warning': '⚠️',
        'info': 'ℹ️',
        'loading': '⏳'
    }
    icon = icon_map.get(status, '•')
    
    print(f"{color}┌─────────────────────────────────────────────────────────────────────────────┐")
    print(f"│ {icon} {Fore.WHITE}{Style.BRIGHT}{message:<72}{color} │")
    print(f"└─────────────────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}")

def print_stats_table(stats_dict, title="📊 Scan Statistics"):
    """Print statistics in a beautiful table"""
    print(f"\n{Fore.YELLOW}╔{'═' * 78}╗")
    print(f"║ {title:<76} ║")
    print(f"╠{'═' * 78}╣")
    
    for key, value in stats_dict.items():
        key_formatted = key.replace('_', ' ').title()
        print(f"║ {Fore.CYAN}{key_formatted:<40}{Fore.WHITE}{Style.BRIGHT}{str(value):>36}{Fore.YELLOW} ║")
    
    print(f"╚{'═' * 78}╝{Style.RESET_ALL}")

def print_menu():
    """Print the main menu with beautiful styling"""
    print_section_header("WayLoot v3.0 - Advanced Features Menu", "🎯")
    
    features = [
        (1, "🔍", "Basic URL Gathering & Snapshot Collection", "Fast reconnaissance with URL discovery and metadata"),
        (2, "📊", "Comprehensive Snapshot Analysis", "Deep analysis with A-Z snapshot downloading"),
        (3, "🧠", "JavaScript Analysis & Endpoint Discovery", "Extract JS files, find API endpoints and secrets"),
        (4, "🔐", "Secret Detection & Vulnerability Scanning", "Advanced pattern matching for sensitive data"),
        (5, "📂", "Parameter Discovery & Wordlist Generation", "Extract parameters and generate custom wordlists"),
        (6, "🌐", "Live Host Detection & Service Discovery", "Multi-threaded subdomain and service scanning"),
        (7, "💎", "Sensitive File Hunter (Advanced)", "Hunt for sensitive files across all snapshots"),
        (8, "🔄", "Resume Previous Scan", "Continue interrupted scans with state management"),
        (9, "🚀", "Full Advanced Scan (All Features)", "Complete reconnaissance with all modules"),
        (10, "⚙️", "Configure Discord Webhook", "Setup real-time notifications and reporting")
    ]
    
    print()
    for num, icon, title, desc in features:
        color = Fore.GREEN if num <= 7 else Fore.YELLOW if num <= 9 else Fore.MAGENTA
        print_feature_box(num, icon, title, desc, color)
        print()
    
    print_feature_box(0, "🚪", "Exit WayLoot", "Thank you for using WayLoot! Happy hunting!", Fore.RED)
    
    print(f"\n{Fore.CYAN}╔{'═' * 78}╗")
    print(f"║ {Fore.YELLOW}{Style.BRIGHT}💡 Pro Tips:{Style.RESET_ALL}                                                        {Fore.CYAN}║")
    print(f"║ {Fore.WHITE}• Use option 9 for maximum reconnaissance coverage{Fore.CYAN}                     ║")
    print(f"║ {Fore.WHITE}• Configure Discord webhook (option 10) for real-time alerts{Fore.CYAN}          ║")
    print(f"║ {Fore.WHITE}• Use resume functionality (option 8) for large targets{Fore.CYAN}               ║")
    print(f"╚{'═' * 78}╝{Style.RESET_ALL}")

def print_footer():
    """Print footer with additional credits"""
    footer = f"""
{Fore.MAGENTA}╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  {Fore.YELLOW}{Style.BRIGHT}🙏 Acknowledgments:{Style.RESET_ALL}                                                     {Fore.MAGENTA}║
║  {Fore.WHITE}• Wayback Machine API for historical data{Fore.MAGENTA}                                ║
║  {Fore.WHITE}• gau & waybackurls tools by @tomnomnom & @lc{Fore.MAGENTA}                            ║
║  {Fore.WHITE}• Bug bounty community for inspiration{Fore.MAGENTA}                                   ║
║                                                                              ║
║  {Fore.RED}{Style.BRIGHT}⚠️  Legal Notice:{Style.RESET_ALL}                                                        {Fore.MAGENTA}║
║  {Fore.WHITE}This tool is for authorized testing only. Respect rate limits and ToS.{Fore.MAGENTA}  ║
║                                                                              ║
║  {Fore.GREEN}{Style.BRIGHT}🌟 Happy Hunting & Stay Ethical! 🌟{Style.RESET_ALL}                                    {Fore.MAGENTA}║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(footer)

# --- Discord Notifier Class ---
class DiscordNotifier:
    def __init__(self, webhook_url):
        self.webhook_url = webhook_url
        self.rate_limit_delay = 1

    def send_message(self, content):
        if not self.webhook_url:
            return
        payload = {'content': content}
        try:
            requests.post(self.webhook_url, json=payload, timeout=10)
            time.sleep(self.rate_limit_delay)
        except requests.RequestException as e:
            log_error(f"Failed to send Discord notification: {e}")

    def send_embed(self, title, description, fields=None, color=0x00ff00):
        if not self.webhook_url:
            return
        embed = {
            "title": title,
            "description": description,
            "color": color,
            "fields": fields or [],
            "footer": {"text": "WayLoot v3.0 by Hamza Iqbal"},
            "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime())
        }
        payload = {"embeds": [embed]}
        try:
            requests.post(self.webhook_url, json=payload, timeout=10)
            time.sleep(self.rate_limit_delay)
        except requests.RequestException as e:
            log_error(f"Failed to send Discord embed: {e}")

    def send_file(self, file_path, message):
        if not self.webhook_url or not os.path.exists(file_path):
            return
        try:
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f)}
                payload = {'content': message}
                requests.post(self.webhook_url, files=files, data=payload, timeout=30)
                time.sleep(self.rate_limit_delay)
        except Exception as e:
            log_error(f"Failed to send Discord file: {e}")

# --- Advanced Analyzer Class ---
class AdvancedAnalyzer:
    def __init__(self, domain_dir, notifier):
        self.domain_dir = domain_dir
        self.notifier = notifier
        self.js_findings_dir = os.path.join(domain_dir, "js_findings")
        self.wordlists_dir = os.path.join(domain_dir, "wordlists")
        os.makedirs(self.js_findings_dir, exist_ok=True)
        os.makedirs(self.wordlists_dir, exist_ok=True)
        
        self.secrets_found = []
        self.api_endpoints = set()
        self.parameters = set()
        self.paths = set()
        self.vulnerabilities = []

    def extract_js_files(self, content, url, timestamp):
        """Extract and analyze JavaScript files"""
        js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', content, re.IGNORECASE)
        
        for js_url in js_urls:
            if not js_url.startswith('http'):
                if js_url.startswith('//'):
                    js_url = 'https:' + js_url
                elif js_url.startswith('/'):
                    parsed_url = urlparse(url)
                    js_url = f"{parsed_url.scheme}://{parsed_url.netloc}{js_url}"
                else:
                    parsed_url = urlparse(url)
                    js_url = f"{parsed_url.scheme}://{parsed_url.netloc}/{js_url}"
            
            self.download_js_file(js_url, timestamp)

    def download_js_file(self, js_url, timestamp):
        """Download and analyze JavaScript file"""
        try:
            headers = {'User-Agent': USER_AGENT}
            response = requests.get(js_url, headers=headers, timeout=30)
            response.raise_for_status()
            
            filename = os.path.basename(urlparse(js_url).path) or 'script.js'
            output_path = os.path.join(self.js_findings_dir, f"{timestamp}_{filename}")
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(response.text)
            
            self.analyze_js_content(response.text, js_url)
            log_success(f"Downloaded JS file: {output_path}")
            
        except Exception as e:
            log_error(f"Failed to download JS file {js_url}: {e}")

    def analyze_js_content(self, content, url):
        """Analyze JavaScript content for secrets and endpoints"""
        for pattern in API_PATTERNS:
            matches = re.findall(pattern, content)
            for match in matches:
                self.api_endpoints.add(match)
        
        for secret_type, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, content)
            for match in matches:
                secret_value = match if isinstance(match, str) else match[1] if len(match) > 1 else match[0]
                self.secrets_found.append({
                    'type': secret_type,
                    'value': secret_value,
                    'url': url,
                    'context': 'JavaScript'
                })
                
                self.notifier.send_embed(
                    title="🔐 Secret Found in JavaScript!",
                    description=f"A potential secret was discovered in JavaScript code.",
                    fields=[
                        {"name": "Type", "value": secret_type, "inline": True},
                        {"name": "Value", "value": f"`{secret_value[:50]}...`", "inline": True},
                        {"name": "Source", "value": f"`{url}`", "inline": False}
                    ],
                    color=0xff0000
                )

    def detect_secrets_in_content(self, content, url, content_type):
        """Detect secrets in any content"""
        for secret_type, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, content)
            for match in matches:
                secret_value = match if isinstance(match, str) else match[1] if len(match) > 1 else match[0]
                self.secrets_found.append({
                    'type': secret_type,
                    'value': secret_value,
                    'url': url,
                    'context': content_type
                })

    def extract_parameters(self, url):
        """Extract parameters from URL"""
        parsed_url = urlparse(url)
        if parsed_url.query:
            params = parse_qs(parsed_url.query)
            for param in params.keys():
                self.parameters.add(param)
        
        if parsed_url.path and parsed_url.path != '/':
            self.paths.add(parsed_url.path)

    def detect_vulnerabilities(self, content, url):
        """Detect potential vulnerabilities"""
        for vuln_type, pattern in VULN_PATTERNS.items():
            if re.search(pattern, content):
                self.vulnerabilities.append({
                    'type': vuln_type,
                    'url': url,
                    'pattern': pattern
                })
                
                self.notifier.send_embed(
                    title="⚠️ Potential Vulnerability Found!",
                    description=f"A potential {vuln_type} vulnerability was detected.",
                    fields=[
                        {"name": "Type", "value": vuln_type, "inline": True},
                        {"name": "URL", "value": f"`{url}`", "inline": False}
                    ],
                    color=0xff9900
                )

    def save_findings(self):
        """Save all findings to files"""
        secrets_file = os.path.join(self.domain_dir, 'secrets.txt')
        with open(secrets_file, 'w') as f:
            f.write("WayLoot Secret Detection Report\n")
            f.write("Developed by Hamza Iqbal\n")
            f.write("=" * 50 + "\n\n")
            for secret in self.secrets_found:
                f.write(f"Type: {secret['type']}\n")
                f.write(f"Value: {secret['value']}\n")
                f.write(f"URL: {secret['url']}\n")
                f.write(f"Context: {secret['context']}\n")
                f.write("-" * 30 + "\n")
        
        params_file = os.path.join(self.domain_dir, 'params.txt')
        with open(params_file, 'w') as f:
            for param in sorted(self.parameters):
                f.write(param + '\n')
        
        api_file = os.path.join(self.domain_dir, 'api_endpoints.txt')
        with open(api_file, 'w') as f:
            for endpoint in sorted(self.api_endpoints):
                f.write(endpoint + '\n')
        
        paths_file = os.path.join(self.wordlists_dir, 'paths.txt')
        with open(paths_file, 'w') as f:
            for path in sorted(self.paths):
                f.write(path + '\n')
        
        vulns_file = os.path.join(self.domain_dir, 'vulnerabilities.txt')
        with open(vulns_file, 'w') as f:
            f.write("WayLoot Vulnerability Detection Report\n")
            f.write("Developed by Hamza Iqbal\n")
            f.write("=" * 50 + "\n\n")
            for vuln in self.vulnerabilities:
                f.write(f"Type: {vuln['type']}\n")
                f.write(f"URL: {vuln['url']}\n")
                f.write(f"Pattern: {vuln['pattern']}\n")
                f.write("-" * 30 + "\n")
        
        return {
            'secrets': len(self.secrets_found),
            'parameters': len(self.parameters),
            'api_endpoints': len(self.api_endpoints),
            'paths': len(self.paths),
            'vulnerabilities': len(self.vulnerabilities)
        }

# --- State Manager for Resume Functionality ---
class StateManager:
    def __init__(self, domain_dir):
        self.state_file = os.path.join(domain_dir, 'state.json')
        self.state = self.load_state()

    def load_state(self):
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {
            'processed_urls': [],
            'downloaded_snapshots': [],
            'last_run': None
        }

    def save_state(self):
        with open(self.state_file, 'w') as f:
            json.dump(self.state, f, indent=2)

    def is_processed(self, item):
        return item in self.state.get('processed_urls', [])

    def mark_processed(self, item):
        if 'processed_urls' not in self.state:
            self.state['processed_urls'] = []
        self.state['processed_urls'].append(item)
        self.save_state()

# --- Live Host Detector ---
class LiveHostDetector:
    def __init__(self, domain_dir, notifier):
        self.domain_dir = domain_dir
        self.notifier = notifier
        self.live_hosts = []

    def extract_subdomains(self, urls):
        """Extract unique subdomains from URLs"""
        subdomains = set()
        for url in urls:
            parsed = urlparse(url)
            if parsed.netloc:
                subdomains.add(parsed.netloc)
        return list(subdomains)

    def check_host_alive(self, host):
        """Check if a host is alive"""
        try:
            response = requests.get(f"http://{host}", timeout=5, allow_redirects=True)
            if response.status_code < 500:
                return {'host': host, 'status': 'alive', 'protocol': 'http', 'status_code': response.status_code}
        except:
            pass
        
        try:
            response = requests.get(f"https://{host}", timeout=5, allow_redirects=True)
            if response.status_code < 500:
                return {'host': host, 'status': 'alive', 'protocol': 'https', 'status_code': response.status_code}
        except:
            pass
        
        return {'host': host, 'status': 'dead', 'protocol': None, 'status_code': None}

    def scan_live_hosts(self, urls, threads=10):
        """Scan for live hosts using threading"""
        subdomains = self.extract_subdomains(urls)
        print_status_box('loading', f"Scanning {len(subdomains)} hosts for live services...", Fore.YELLOW)
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_host = {executor.submit(self.check_host_alive, host): host for host in subdomains}
            
            for future in tqdm(as_completed(future_to_host), total=len(subdomains), desc="🌐 Scanning hosts"):
                result = future.result()
                if result['status'] == 'alive':
                    self.live_hosts.append(result)
                    log_success(f"Live host found: {result['protocol']}://{result['host']} ({result['status_code']})")
                    
                    self.notifier.send_embed(
                        title="🌐 Live Host Detected!",
                        description=f"A live host was discovered during the scan.",
                        fields=[
                            {"name": "Host", "value": result['host'], "inline": True},
                            {"name": "Protocol", "value": result['protocol'], "inline": True},
                            {"name": "Status Code", "value": str(result['status_code']), "inline": True}
                        ],
                        color=0x00ff00
                    )

        live_hosts_file = os.path.join(self.domain_dir, 'live_hosts.txt')
        with open(live_hosts_file, 'w') as f:
            f.write("WayLoot Live Host Detection Report\n")
            f.write("Developed by Hamza Iqbal\n")
            f.write("=" * 50 + "\n\n")
            for host in self.live_hosts:
                f.write(f"{host['protocol']}://{host['host']} - Status: {host['status_code']}\n")
        
        return len(self.live_hosts)

# --- Logging Functions ---
def log_info(message):
    print(f"{Fore.BLUE}[ℹ️]{Style.RESET_ALL} {message}")

def log_success(message):
    print(f"{Fore.GREEN}[✅]{Style.RESET_ALL} {message}")

def log_warning(message):
    print(f"{Fore.YELLOW}[⚠️]{Style.RESET_ALL} {message}")

def log_error(message):
    print(f"{Fore.RED}[❌]{Style.RESET_ALL} {message}")

def log_download(message):
    print(f"{Fore.CYAN}[📥]{Style.RESET_ALL} {message}")

# --- Core Functions ---
def check_tool_installed(name):
    from shutil import which
    if which(name) is None:
        print_status_box('error', f"Tool '{name}' not found. Please install it first.", Fore.RED)
        log_info(f"Installation: go install github.com/tomnomnom/waybackurls@latest")
        log_info(f"Installation: go install github.com/lc/gau/v2/cmd/gau@latest")
        return False
    return True

def get_urls(domain, data_dir, notifier, state_manager):
    print_status_box('loading', f"Gathering URLs for {domain} using gau and waybackurls...", Fore.YELLOW)
    notifier.send_message(f"🔍 Starting URL gathering for `{domain}`...")

    if not check_tool_installed('gau') or not check_tool_installed('waybackurls'):
        notifier.send_message(f"❌ URL gathering failed for `{domain}`. Required tools are not installed.")
        sys.exit(1)

    urls = set()
    try:
        gau_process = subprocess.Popen(['gau', domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in gau_process.stdout:
            urls.add(line.strip())
        
        wayback_process = subprocess.Popen(['waybackurls', domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in wayback_process.stdout:
            urls.add(line.strip())

        gau_process.wait()
        wayback_process.wait()
    except Exception as e:
        print_status_box('error', f"Error running URL gathering tools: {e}", Fore.RED)
        notifier.send_message(f"❌ An error occurred during URL gathering for `{domain}`.")
        return []

    if not urls:
        print_status_box('warning', "No URLs found. Exiting.", Fore.YELLOW)
        notifier.send_message(f"⚠️ No URLs found for `{domain}`.")
        return []

    urls_path = os.path.join(data_dir, 'urls.txt')
    sorted_urls = sorted(list(urls))
    with open(urls_path, 'w') as f:
        for url in sorted_urls:
            f.write(url + '\n')
    
    print_status_box('success', f"Found {len(urls)} unique URLs. Saved to {urls_path}", Fore.GREEN)
    notifier.send_message(f"✅ Found `{len(urls)}` unique URLs for `{domain}`.")
    notifier.send_file(urls_path, f"📋 Full URL list for `{domain}`:")
    return sorted_urls

def get_snapshots(url):
    params = {'url': url, 'output': 'json', 'limit': 100000}
    headers = {'User-Agent': USER_AGENT}
    try:
        response = requests.get(CDX_API_URL, params=params, headers=headers, timeout=30)
        response.raise_for_status()
        snapshots = response.json()
        if snapshots and len(snapshots) > 1:
            return snapshots[1:]
    except (requests.RequestException, json.JSONDecodeError):
        pass
    return []

def interactive_mode():
    """Interactive menu-driven mode"""
    print_header()
    
    domain = input(f"\n{Fore.CYAN}🎯 Enter target domain (e.g., example.com): {Style.RESET_ALL}").strip()
    if not domain:
        print_status_box('error', "Domain is required!", Fore.RED)
        return
    
    base_dir = "data"
    domain_dir = os.path.join(base_dir, domain)
    os.makedirs(domain_dir, exist_ok=True)
    
    webhook_url = None
    notifier = DiscordNotifier(webhook_url)
    analyzer = AdvancedAnalyzer(domain_dir, notifier)
    state_manager = StateManager(domain_dir)
    live_detector = LiveHostDetector(domain_dir, notifier)
    
    while True:
        print_menu()
        choice = input(f"\n{Fore.CYAN}🎯 Select an option (0-10): {Style.RESET_ALL}").strip()
        
        if choice == '0':
            print_footer()
            print_status_box('success', "Thank you for using WayLoot! Happy hunting! 🎯", Fore.GREEN)
            break
        elif choice == '1':
            basic_scan(domain, domain_dir, notifier, state_manager)
        elif choice == '2':
            comprehensive_scan(domain, domain_dir, notifier, analyzer, state_manager)
        elif choice == '3':
            javascript_analysis(domain, domain_dir, notifier, analyzer, state_manager)
        elif choice == '4':
            secret_vulnerability_scan(domain, domain_dir, notifier, analyzer, state_manager)
        elif choice == '5':
            parameter_wordlist_generation(domain, domain_dir, notifier, analyzer, state_manager)
        elif choice == '6':
            live_host_detection(domain, domain_dir, notifier, live_detector, state_manager)
        elif choice == '7':
            advanced_sensitive_hunter(domain, domain_dir, notifier, analyzer, state_manager)
        elif choice == '8':
            resume_scan(domain, domain_dir, notifier, analyzer, state_manager)
        elif choice == '9':
            full_advanced_scan(domain, domain_dir, notifier, analyzer, state_manager, live_detector)
        elif choice == '10':
            webhook_url = configure_discord_webhook()
            notifier = DiscordNotifier(webhook_url)
            analyzer.notifier = notifier
            live_detector.notifier = notifier
        else:
            print_status_box('warning', "Invalid option! Please select 0-10.", Fore.YELLOW)

def configure_discord_webhook():
    """Configure Discord webhook"""
    print_section_header("Discord Webhook Configuration", "🔗")
    print(f"{Fore.CYAN}To get a webhook URL:")
    print(f"1. Go to your Discord server settings")
    print(f"2. Navigate to Integrations → Webhooks")
    print(f"3. Create a new webhook and copy the URL{Style.RESET_ALL}")
    
    webhook_url = input(f"\n{Fore.CYAN}Enter Discord webhook URL (or press Enter to skip): {Style.RESET_ALL}").strip()
    
    if webhook_url:
        test_notifier = DiscordNotifier(webhook_url)
        test_notifier.send_message("🎉 WayLoot Discord integration configured successfully by Hamza Iqbal!")
        print_status_box('success', "Discord webhook configured and tested!", Fore.GREEN)
        return webhook_url
    else:
        print_status_box('info', "Discord webhook skipped.", Fore.BLUE)
        return None

def basic_scan(domain, domain_dir, notifier, state_manager):
    """Basic URL gathering and snapshot collection"""
    print_section_header("Basic Scan", "🔍")
    notifier.send_message(f"🔍 Starting basic scan for `{domain}`...")
    
    urls = get_urls(domain, domain_dir, notifier, state_manager)
    if not urls:
        return
    
    all_snapshots = []
    snapshots_log_path = os.path.join(domain_dir, 'snapshots.txt')
    
    with open(snapshots_log_path, 'w') as log_file:
        log_file.write("timestamp,status,url\n")
        
        for url in tqdm(urls, desc="🔍 Processing URLs"):
            snapshots = get_snapshots(url)
            for snapshot in snapshots:
                if len(snapshot) >= 4:
                    timestamp, original_url, _, status_code = snapshot[1:5]
                    all_snapshots.append((timestamp, status_code, original_url))
                    log_file.write(f"{timestamp},{status_code},{original_url}\n")
    
    stats = {
        'Total URLs': len(urls),
        'Total Snapshots': len(all_snapshots),
        'Scan Type': 'Basic'
    }
    
    print_stats_table(stats, "📊 Basic Scan Results")
    print_status_box('success', f"Basic scan complete! Found {len(all_snapshots)} snapshots.", Fore.GREEN)
    notifier.send_message(f"✅ Basic scan complete for `{domain}`! Found `{len(all_snapshots)}` snapshots.")
    notifier.send_file(snapshots_log_path, f"📊 Snapshot metadata for `{domain}`:")

def comprehensive_scan(domain, domain_dir, notifier, analyzer, state_manager):
    """Comprehensive snapshot analysis with full download"""
    print_section_header("Comprehensive Scan", "📊")
    notifier.send_message(f"📊 Starting comprehensive scan for `{domain}`...")
    
    urls = get_urls(domain, domain_dir, notifier, state_manager)
    if not urls:
        return
    
    archive_dir = os.path.join(domain_dir, "archive_snapshots")
    os.makedirs(archive_dir, exist_ok=True)
    
    total_downloaded = 0
    for url in tqdm(urls, desc="📊 Comprehensive Analysis"):
        snapshots = get_snapshots(url)
        for snapshot in snapshots:
            if len(snapshot) >= 6:
                timestamp, original_url, mimetype, statuscode, _, _ = snapshot[1:7]
                
                parsed_url = urlparse(original_url)
                url_path = f"{parsed_url.netloc}{parsed_url.path}".replace('/', '_').replace('\\', '_')
                url_folder = os.path.join(archive_dir, url_path[:100])
                os.makedirs(url_folder, exist_ok=True)
                
                snapshot_url = f"{WAYBACK_BASE_URL}{timestamp}id_/{original_url}"
                output_path = os.path.join(url_folder, f"{timestamp}_{statuscode}.html")
                
                if not os.path.exists(output_path):
                    try:
                        headers = {'User-Agent': USER_AGENT}
                        response = requests.get(snapshot_url, headers=headers, timeout=30)
                        response.raise_for_status()
                        
                        with open(output_path, 'wb') as f:
                            f.write(response.content)
                        
                        total_downloaded += 1
                        
                        if 'text' in mimetype.lower():
                            content = response.content.decode('utf-8', errors='ignore')
                            analyzer.detect_secrets_in_content(content, original_url, 'HTML')
                            analyzer.detect_vulnerabilities(content, original_url)
                            analyzer.extract_js_files(content, original_url, timestamp)
                        
                    except Exception:
                        pass
    
    stats = {
        'Total URLs': len(urls),
        'Snapshots Downloaded': total_downloaded,
        'Scan Type': 'Comprehensive'
    }
    
    print_stats_table(stats, "📊 Comprehensive Scan Results")
    print_status_box('success', f"Comprehensive scan complete! Downloaded {total_downloaded} snapshots.", Fore.GREEN)
    notifier.send_message(f"✅ Comprehensive scan complete for `{domain}`! Downloaded `{total_downloaded}` snapshots.")

def javascript_analysis(domain, domain_dir, notifier, analyzer, state_manager):
    """JavaScript analysis and endpoint discovery"""
    print_section_header("JavaScript Analysis", "🧠")
    notifier.send_message(f"🧠 Starting JavaScript analysis for `{domain}`...")
    
    urls = get_urls(domain, domain_dir, notifier, state_manager)
    if not urls:
        return
    
    js_count = 0
    for url in tqdm(urls, desc="🧠 JS Analysis"):
        if any(url.lower().endswith(ext) for ext in JS_EXTENSIONS):
            try:
                headers = {'User-Agent': USER_AGENT}
                response = requests.get(url, headers=headers, timeout=30)
                response.raise_for_status()
                
                filename = os.path.basename(urlparse(url).path) or 'script.js'
                output_path = os.path.join(analyzer.js_findings_dir, f"live_{filename}")
                
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(response.text)
                
                analyzer.analyze_js_content(response.text, url)
                js_count += 1
                
            except Exception:
                pass
    
    findings = analyzer.save_findings()
    
    stats = {
        'JS Files Analyzed': js_count,
        'API Endpoints Found': findings['api_endpoints'],
        'Secrets Discovered': findings['secrets']
    }
    
    print_stats_table(stats, "🧠 JavaScript Analysis Results")
    print_status_box('success', f"JavaScript analysis complete! Analyzed {js_count} JS files.", Fore.GREEN)
    
    notifier.send_message(f"✅ JavaScript analysis complete for `{domain}`!")
    notifier.send_embed(
        title="🧠 JavaScript Analysis Results",
        description=f"Analysis completed for `{domain}`",
        fields=[
            {"name": "JS Files Analyzed", "value": str(js_count), "inline": True},
            {"name": "API Endpoints", "value": str(findings['api_endpoints']), "inline": True},
            {"name": "Secrets Found", "value": str(findings['secrets']), "inline": True}
        ],
        color=0x0099ff
    )

def secret_vulnerability_scan(domain, domain_dir, notifier, analyzer, state_manager):
    """Secret detection and vulnerability scanning"""
    print_section_header("Secret & Vulnerability Scan", "🔐")
    notifier.send_message(f"🔐 Starting secret & vulnerability scan for `{domain}`...")
    
    urls = get_urls(domain, domain_dir, notifier, state_manager)
    if not urls:
        return
    
    scanned_count = 0
    for url in tqdm(urls, desc="🔐 Secret/Vuln Scan"):
        try:
            headers = {'User-Agent': USER_AGENT}
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            
            content = response.text
            analyzer.detect_secrets_in_content(content, url, 'Live Site')
            analyzer.detect_vulnerabilities(content, url)
            scanned_count += 1
            
        except Exception:
            pass
    
    findings = analyzer.save_findings()
    
    stats = {
        'URLs Scanned': scanned_count,
        'Secrets Found': findings['secrets'],
        'Vulnerabilities': findings['vulnerabilities']
    }
    
    print_stats_table(stats, "🔐 Security Scan Results")
    print_status_box('success', f"Security scan complete! Scanned {scanned_count} URLs.", Fore.GREEN)
    notifier.send_message(f"✅ Secret & vulnerability scan complete for `{domain}`!")

def parameter_wordlist_generation(domain, domain_dir, notifier, analyzer, state_manager):
    """Parameter discovery and wordlist generation"""
    print_section_header("Parameter Discovery", "📂")
    notifier.send_message(f"📂 Starting parameter discovery for `{domain}`...")
    
    urls = get_urls(domain, domain_dir, notifier, state_manager)
    if not urls:
        return
    
    for url in tqdm(urls, desc="📂 Parameter Discovery"):
        analyzer.extract_parameters(url)
    
    findings = analyzer.save_findings()
    
    stats = {
        'URLs Processed': len(urls),
        'Parameters Found': findings['parameters'],
        'Paths Discovered': findings['paths']
    }
    
    print_stats_table(stats, "📂 Parameter Discovery Results")
    print_status_box('success', f"Parameter discovery complete!", Fore.GREEN)
    
    notifier.send_message(f"✅ Parameter discovery complete for `{domain}`!")
    notifier.send_file(os.path.join(domain_dir, 'params.txt'), f"📋 Parameters for `{domain}`:")
    notifier.send_file(os.path.join(analyzer.wordlists_dir, 'paths.txt'), f"📂 Path wordlist for `{domain}`:")

def live_host_detection(domain, domain_dir, notifier, live_detector, state_manager):
    """Live host detection and service discovery"""
    print_section_header("Live Host Detection", "🌐")
    notifier.send_message(f"🌐 Starting live host detection for `{domain}`...")
    
    urls = get_urls(domain, domain_dir, notifier, state_manager)
    if not urls:
        return
    
    live_count = live_detector.scan_live_hosts(urls, threads=20)
    
    stats = {
        'Total Hosts Scanned': len(live_detector.extract_subdomains(urls)),
        'Live Hosts Found': live_count,
        'Success Rate': f"{(live_count/len(live_detector.extract_subdomains(urls))*100):.1f}%" if live_detector.extract_subdomains(urls) else "0%"
    }
    
    print_stats_table(stats, "🌐 Live Host Detection Results")
    print_status_box('success', f"Live host detection complete! Found {live_count} live hosts.", Fore.GREEN)
    notifier.send_message(f"✅ Live host detection complete for `{domain}`! Found `{live_count}` live hosts.")
    notifier.send_file(os.path.join(domain_dir, 'live_hosts.txt'), f"🌐 Live hosts for `{domain}`:")

def advanced_sensitive_hunter(domain, domain_dir, notifier, analyzer, state_manager):
    """Advanced sensitive file hunting"""
    print_section_header("Advanced Sensitive File Hunt", "💎")
    notifier.send_message(f"💎 Starting advanced sensitive file hunt for `{domain}`...")
    
    urls = get_urls(domain, domain_dir, notifier, state_manager)
    if not urls:
        return
    
    sensitive_dir = os.path.join(domain_dir, "sensitive_files")
    os.makedirs(sensitive_dir, exist_ok=True)
    
    sensitive_count = 0
    for url in tqdm(urls, desc="💎 Sensitive Hunt"):
        if any(url.lower().endswith(ext) for ext in SENSITIVE_EXTENSIONS):
            snapshots = get_snapshots(url)
            for snapshot in snapshots:
                if len(snapshot) >= 4:
                    timestamp, original_url, _, status_code = snapshot[1:5]
                    if status_code.startswith('2'):
                        try:
                            snapshot_url = f"{WAYBACK_BASE_URL}{timestamp}id_/{original_url}"
                            filename = os.path.basename(unquote(original_url))
                            output_path = os.path.join(sensitive_dir, f"{timestamp}_{filename}")
                            
                            if not os.path.exists(output_path):
                                headers = {'User-Agent': USER_AGENT}
                                response = requests.get(snapshot_url, headers=headers, timeout=30)
                                response.raise_for_status()
                                
                                with open(output_path, 'wb') as f:
                                    f.write(response.content)
                                
                                sensitive_count += 1
                                
                                notifier.send_embed(
                                    title="💎 Sensitive File Found!",
                                    description=f"A sensitive file was discovered and downloaded.",
                                    fields=[
                                        {"name": "File", "value": filename, "inline": True},
                                        {"name": "Timestamp", "value": timestamp, "inline": True},
                                        {"name": "URL", "value": f"`{original_url}`", "inline": False}
                                    ],
                                    color=0xff6600
                                )
                        except Exception:
                            pass
    
    stats = {
        'URLs Processed': len(urls),
        'Sensitive Files Found': sensitive_count,
        'File Types': len(SENSITIVE_EXTENSIONS)
    }
    
    print_stats_table(stats, "💎 Sensitive File Hunt Results")
    print_status_box('success', f"Advanced sensitive file hunt complete! Found {sensitive_count} files.", Fore.GREEN)
    notifier.send_message(f"✅ Advanced sensitive file hunt complete for `{domain}`! Found `{sensitive_count}` files.")

def resume_scan(domain, domain_dir, notifier, analyzer, state_manager):
    """Resume previous scan"""
    print_section_header("Resume Previous Scan", "🔄")
    
    if not state_manager.state.get('last_run'):
        print_status_box('warning', "No previous scan found to resume.", Fore.YELLOW)
        return
    
    print_status_box('info', f"Resuming scan from {state_manager.state['last_run']}", Fore.BLUE)
    print_status_box('info', f"Previously processed: {len(state_manager.state.get('processed_urls', []))} URLs", Fore.BLUE)
    
    basic_scan(domain, domain_dir, notifier, state_manager)

def full_advanced_scan(domain, domain_dir, notifier, analyzer, state_manager, live_detector):
    """Full advanced scan with all features"""
    print_section_header("Full Advanced Scan (All Features)", "🚀")
    notifier.send_message(f"🚀 Starting FULL advanced scan for `{domain}` - This will take a while!")
    
    start_time = time.time()
    
    print_status_box('loading', "Running all scan modules sequentially...", Fore.YELLOW)
    
    basic_scan(domain, domain_dir, notifier, state_manager)
    comprehensive_scan(domain, domain_dir, notifier, analyzer, state_manager)
    javascript_analysis(domain, domain_dir, notifier, analyzer, state_manager)
    secret_vulnerability_scan(domain, domain_dir, notifier, analyzer, state_manager)
    parameter_wordlist_generation(domain, domain_dir, notifier, analyzer, state_manager)
    live_host_detection(domain, domain_dir, notifier, live_detector, state_manager)
    advanced_sensitive_hunter(domain, domain_dir, notifier, analyzer, state_manager)
    
    findings = analyzer.save_findings()
    end_time = time.time()
    duration = int(end_time - start_time)
    
    final_stats = {
        'Scan Duration': f"{duration} seconds",
        'Secrets Found': findings['secrets'],
        'API Endpoints': findings['api_endpoints'],
        'Parameters': findings['parameters'],
        'Vulnerabilities': findings['vulnerabilities'],
        'Paths': findings['paths'],
        'Live Hosts': len(live_detector.live_hosts)
    }
    
    print_stats_table(final_stats, "🎉 Full Advanced Scan Complete!")
    print_status_box('success', f"Full advanced scan complete! Duration: {duration} seconds", Fore.GREEN)
    
    notifier.send_embed(
        title="🎉 Full Advanced Scan Complete!",
        description=f"Complete reconnaissance finished for `{domain}`",
        fields=[
            {"name": "Duration", "value": f"{duration} seconds", "inline": True},
            {"name": "Secrets Found", "value": str(findings['secrets']), "inline": True},
            {"name": "API Endpoints", "value": str(findings['api_endpoints']), "inline": True},
            {"name": "Parameters", "value": str(findings['parameters']), "inline": True},
            {"name": "Vulnerabilities", "value": str(findings['vulnerabilities']), "inline": True},
            {"name": "Paths", "value": str(findings['paths']), "inline": True}
        ],
        color=0x00ff00
    )

def main():
    """Main function - entry point"""
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(description="WayLoot v3.0 - Advanced Bug Bounty Tool by Hamza Iqbal")
        parser.add_argument('--domain', required=True, help="Target domain")
        parser.add_argument('--webhook-url', help="Discord webhook URL")
        parser.add_argument('--threads', type=int, default=10, help="Number of threads")
        args = parser.parse_args()
        
        domain_dir = os.path.join("data", args.domain)
        os.makedirs(domain_dir, exist_ok=True)
        
        notifier = DiscordNotifier(args.webhook_url)
        analyzer = AdvancedAnalyzer(domain_dir, notifier)
        state_manager = StateManager(domain_dir)
        
        basic_scan(args.domain, domain_dir, notifier, state_manager)
    else:
        interactive_mode()

if __name__ == "__main__":
    main()
