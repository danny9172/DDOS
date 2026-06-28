#!/usr/bin/env python3
"""
DDOS Bro! - Professional Log Analyzer
Version: 1.3 - Fully Fixed
"""

import os
import sys
import subprocess
import importlib.util

# ============================================
# AUTO-INSTALL DEPENDENCIES
# ============================================
def install_package(package):
    try:
        print(f"📦 Installing {package}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", package])
        return True
    except subprocess.CalledProcessError:
        print(f"❌ Failed to install {package}")
        return False

def check_and_install_dependencies():
    required_packages = {'tqdm': 'tqdm', 'requests': 'requests'}
    missing_packages = []
    
    for module_name, package_name in required_packages.items():
        if importlib.util.find_spec(module_name) is None:
            missing_packages.append(package_name)
    
    if missing_packages:
        print(f"\n📦 Missing dependencies: {', '.join(missing_packages)}")
        print("🔄 Installing automatically...\n")
        for package in missing_packages:
            if not install_package(package):
                print(f"⚠️  Could not install {package}. Some features may be limited.")
                return False
        print("\n✅ All dependencies installed successfully!\n")
        return True
    return True

check_and_install_dependencies()

# ============================================
# IMPORTS
# ============================================
import re
import time
import threading
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path
from typing import Dict, List, Tuple, Optional

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

# ============================================
# CONFIGURATION
# ============================================
VERSION = "1.3"
TOP_COUNT = 20
TEMP_DIR = "/tmp/ddos_bro"

class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    PURPLE = '\033[0;35m'
    CYAN = '\033[0;36m'
    WHITE = '\033[1;37m'
    BOLD = '\033[1m'
    NC = '\033[0m'

# ============================================
# UTILITY FUNCTIONS
# ============================================
def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def print_header():
    clear_screen()
    print(f"{Colors.CYAN}═══════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"{Colors.GREEN}{Colors.BOLD}    🛡️  DDOS BRO! - Professional Log Analyzer v{VERSION}{Colors.NC}")
    print(f"{Colors.CYAN}═══════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"{Colors.YELLOW}    Real-time DDoS detection and log analysis tool{Colors.NC}")
    print(f"{Colors.CYAN}═══════════════════════════════════════════════════════════════{Colors.NC}\n")

def print_footer():
    print(f"\n{Colors.CYAN}═══════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"{Colors.GREEN}    🛡️  DDOS Bro! - Always watching your traffic{Colors.NC}")
    print(f"{Colors.CYAN}═══════════════════════════════════════════════════════════════{Colors.NC}")

def detect_timezone(log_file: str) -> str:
    try:
        with open(log_file, 'r') as f:
            first_line = f.readline()
            match = re.search(r'\[([^\]]+)\]', first_line)
            if match:
                timestamp = match.group(1)
                if re.search(r'[+-]\d{4}$', timestamp):
                    return "UTC"
                elif "IST" in timestamp:
                    return "IST"
    except:
        pass
    return "UTC"

def get_log_timestamp(line: str) -> Optional[str]:
    match = re.search(r'\[([^\]]+)\]', line)
    return match.group(1) if match else None

def convert_to_ist(log_time: str) -> str:
    try:
        parts = re.split(r'[/:]', log_time)
        if len(parts) >= 4:
            day, month, year = parts[0], parts[1], parts[2]
            hour, minute, second = parts[3], parts[4], parts[5]
            month_map = {'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04', 
                        'May': '05', 'Jun': '06', 'Jul': '07', 'Aug': '08',
                        'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'}
            month = month_map.get(month, month)
            offset_match = re.search(r'([+-]\d{4})', log_time)
            offset = offset_match.group(1) if offset_match else '+0000'
            dt_str = f"{year}-{month}-{day} {hour}:{minute}:{second} {offset}"
            dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S %z")
            ist_time = dt.astimezone(datetime.timezone(timedelta(hours=5, minutes=30)))
            return ist_time.strftime("%Y-%m-%d %H:%M:%S IST")
    except:
        return "N/A"
    return "N/A"

# ============================================
# CORE LOG PARSER
# ============================================
class LogParser:
    def __init__(self, log_file: str):
        self.log_file = log_file
        self.temp_dir = Path(TEMP_DIR)
        self.temp_dir.mkdir(exist_ok=True)
        
        self.ip_count = Counter()
        self.ua_count = Counter()
        self.url_count = Counter()
        self.query_count = Counter()
        self.status_count = Counter()
        self.hourly_ok = defaultdict(int)
        self.hourly_range = {}
        
        self.total_requests = 0
        self.total_ok = 0
        self.total_403 = 0
        self.total_errors = 0
        
        self.is_processing = False
        self.is_done = False
        self.progress = 0
        
    def parse_in_background(self, start_time: str, end_time: str):
        self.is_processing = True
        self.is_done = False
        self.progress = 0
        thread = threading.Thread(target=self._parse_logs, args=(start_time, end_time))
        thread.daemon = True
        thread.start()
        
    def _parse_logs(self, start_time: str, end_time: str):
        try:
            total_lines = 0
            processed_lines = 0
            
            with open(self.log_file, 'r') as f:
                total_lines = sum(1 for _ in f)
            
            with open(self.log_file, 'r') as f:
                for line in f:
                    processed_lines += 1
                    self.progress = int((processed_lines / total_lines) * 100) if total_lines > 0 else 0
                    
                    ts = get_log_timestamp(line)
                    if not ts:
                        continue
                    
                    # Clean for comparison
                    ts_clean = ts.split(' +')[0]
                    start_clean = start_time.replace('[', '').replace(']', '')
                    end_clean = end_time.replace('[', '').replace(']', '')
                    
                    if ts_clean < start_clean or ts_clean > end_clean:
                        continue
                    
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    
                    status = parts[8] if len(parts) > 8 else "0"
                    ip = parts[0]
                    
                    if status == "403":
                        self.total_403 += 1
                        self.status_count[status] += 1
                        continue
                    
                    self.total_requests += 1
                    self.status_count[status] += 1
                    
                    if status in ["200", "304"]:
                        self.total_ok += 1
                        self.ip_count[ip] += 1
                        
                        url = parts[6] if len(parts) > 6 else "/"
                        self.url_count[url] += 1
                        
                        if '?' in url:
                            query = url.split('?', 1)[1]
                            self.query_count[query] += 1
                        else:
                            self.query_count["(no query)"] += 1
                        
                        if match := re.search(r'(\d{2}:\d{2})', ts):
                            hour = match.group(1)
                            if hour not in self.hourly_ok:
                                self.hourly_ok[hour] = 0
                                self.hourly_range[f"{hour}_start"] = ts
                            self.hourly_ok[hour] += 1
                            self.hourly_range[f"{hour}_end"] = ts
                    else:
                        self.total_errors += 1
                    
                    ua_match = re.search(r'"[^"]*"$', line)
                    if ua_match:
                        ua = ua_match.group(0).strip('"')
                        if ua and ua != "-":
                            self.ua_count[ua] += 1
            
            self.is_done = True
            self.is_processing = False
            
        except Exception as e:
            self.is_processing = False
            self.is_done = True
            print(f"{Colors.RED}Error parsing logs: {e}{Colors.NC}")
    
    def get_progress(self) -> int:
        return self.progress
    
    def is_ready(self) -> bool:
        return self.is_done
    
    def get_results(self) -> dict:
        return {
            'ip_count': self.ip_count,
            'ua_count': self.ua_count,
            'url_count': self.url_count,
            'query_count': self.query_count,
            'status_count': self.status_count,
            'hourly_ok': self.hourly_ok,
            'hourly_range': self.hourly_range,
            'total_requests': self.total_requests,
            'total_ok': self.total_ok,
            'total_403': self.total_403,
            'total_errors': self.total_errors
        }

# ============================================
# GEOIP FUNCTIONS
# ============================================
def get_geo_info(ip: str) -> Tuple[str, str]:
    country = "Unknown"
    asn = "-"
    
    try:
        result = subprocess.run(['geoiplookup', ip], capture_output=True, text=True, timeout=2)
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            if lines:
                country = lines[0].split(': ')[-1].split(',')[0]
    except:
        pass
    
    if country == "Unknown" and HAS_REQUESTS:
        try:
            response = requests.get(f"http://ip-api.com/csv/{ip}?fields=countryCode,as", timeout=2)
            if response.status_code == 200:
                parts = response.text.strip().split(',')
                if len(parts) >= 2:
                    country = parts[0]
                    asn = parts[1].split()[0] if parts[1] else "-"
        except:
            pass
    
    return country, asn

# ============================================
# DISPLAY FUNCTIONS
# ============================================
def display_summary(results: dict):
    total = results['total_requests']
    ok = results['total_ok']
    errors = results['total_errors']
    forbidden = results['total_403']
    pct = int((errors / total * 100) if total > 0 else 0)
    
    print(f"\n{Colors.BLUE}═══════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"{Colors.GREEN}📊 SUMMARY{Colors.NC}")
    print(f"{Colors.BLUE}═══════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"  Total Requests:  {Colors.YELLOW}{total:,}{Colors.NC}")
    print(f"  Total 200 OK:    {Colors.GREEN}{ok:,}{Colors.NC}")
    print(f"  Total Errors:    {Colors.RED}{errors:,}{Colors.NC} ({pct}%)")
    print(f"  403 Excluded:    {Colors.PURPLE}{forbidden:,}{Colors.NC}")
    print(f"{Colors.BLUE}───────────────────────────────────────────────────────────────{Colors.NC}")

def display_top_ips(results: dict, count: int = TOP_COUNT):
    ip_list = results['ip_count'].most_common(count)
    if not ip_list:
        print(f"\n{Colors.YELLOW}No IP data available{Colors.NC}")
        return
    
    print(f"\n{Colors.BLUE}═══════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"{Colors.GREEN}🌐 TOP {count} IP ADDRESSES{Colors.NC}")
    print(f"{Colors.BLUE}═══════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"{Colors.CYAN}#  HITS  IP ADDRESS         COUNTRY          ASN{Colors.NC}")
    print(f"{Colors.BLUE}───────────────────────────────────────────────────────────────{Colors.NC}")
    
    for idx, (ip, hits) in enumerate(ip_list, 1):
        country, asn = get_geo_info(ip)
        print(f"{idx:2}  {hits:6}  {ip:18} {country:15} {asn}")

def display_top_ua(results: dict, count: int = TOP_COUNT):
    ua_list = results['ua_count'].most_common(count)
    if not ua_list:
        print(f"\n{Colors.YELLOW}No User-Agent data available{Colors.NC}")
        return
    
    print(f"\n{Colors.BLUE}═══════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"{Colors.GREEN}🤖 TOP {count} USER AGENTS{Colors.NC}")
    print(f"{Colors.BLUE}═══════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"{Colors.CYAN}#  HITS  USER AGENT{Colors.NC}")
    print(f"{Colors.BLUE}───────────────────────────────────────────────────────────────{Colors.NC}")
    
    for idx, (ua, hits) in enumerate(ua_list, 1):
        print(f"{idx:2}  {hits:6}  {ua[:80]}{'...' if len(ua) > 80 else ''}")

def display_top_urls(results: dict, count: int = TOP_COUNT):
    url_list = results['url_count'].most_common(count)
    if not url_list:
        print(f"\n{Colors.YELLOW}No URL data available{Colors.NC}")
        return
    
    print(f"\n{Colors.BLUE}═══════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"{Colors.GREEN}📁 TOP {count} REQUESTED URLS{Colors.NC}")
    print(f"{Colors.BLUE}═══════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"{Colors.CYAN}#  HITS  URL{Colors.NC}")
    print(f"{Colors.BLUE}───────────────────────────────────────────────────────────────{Colors.NC}")
    
    for idx, (url, hits) in enumerate(url_list, 1):
        print(f"{idx:2}  {hits:6}  {url[:80]}{'...' if len(url) > 80 else ''}")

def display_top_queries(results: dict, count: int = TOP_COUNT):
    query_list = results['query_count'].most_common(count)
    if not query_list:
        print(f"\n{Colors.YELLOW}No query data available{Colors.NC}")
        return
    
    print(f"\n{Colors.BLUE}═══════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"{Colors.GREEN}🔍 TOP {count} QUERY STRINGS{Colors.NC}")
    print(f"{Colors.BLUE}═══════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"{Colors.CYAN}#  HITS  QUERY STRING{Colors.NC}")
    print(f"{Colors.BLUE}───────────────────────────────────────────────────────────────{Colors.NC}")
    
    for idx, (query, hits) in enumerate(query_list, 1):
        print(f"{idx:2}  {hits:6}  {query[:80]}{'...' if len(query) > 80 else ''}")

def display_status(results: dict):
    status_list = results['status_count'].most_common()
    if not status_list:
        print(f"\n{Colors.YELLOW}No status data available{Colors.NC}")
        return
    
    print(f"\n{Colors.BLUE}═══════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"{Colors.GREEN}📈 HTTP STATUS BREAKDOWN{Colors.NC}")
    print(f"{Colors.BLUE}═══════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"{Colors.CYAN}STATUS  COUNT{Colors.NC}")
    print(f"{Colors.BLUE}───────────────────────────────────────────────────────────────{Colors.NC}")
    
    for status, count in status_list:
        if status == "403":
            color = Colors.PURPLE
            suffix = " (excluded)"
        elif status.startswith('2'):
            color = Colors.GREEN
            suffix = ""
        elif status.startswith('3'):
            color = Colors.YELLOW
            suffix = ""
        elif status.startswith('4'):
            color = Colors.PURPLE
            suffix = ""
        elif status.startswith('5'):
            color = Colors.RED
            suffix = ""
        else:
            color = Colors.NC
            suffix = ""
        
        print(f"{color}{status:6}{Colors.NC}  {count:,}{suffix}")

def display_hourly(results: dict):
    """Display hourly stats with proper time range"""
    hourly_items = sorted(results['hourly_ok'].items())
    if not hourly_items:
        print(f"\n{Colors.YELLOW}No hourly data available{Colors.NC}")
        return
    
    print(f"\n{Colors.BLUE}═══════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"{Colors.GREEN}⏰ HOURLY 200 OK REQUESTS{Colors.NC}")
    print(f"{Colors.BLUE}═══════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"{Colors.CYAN}TIME FROM → TIME TO                    |  HITS{Colors.NC}")
    print(f"{Colors.BLUE}───────────────────────────────────────────────────────────────{Colors.NC}")
    
    for hour, count in hourly_items:
        start = results['hourly_range'].get(f"{hour}_start", "N/A")
        end = results['hourly_range'].get(f"{hour}_end", "N/A")
        
        # Clean up timestamps - remove timezone
        start = re.sub(r' [+-]\d{4}', '', start)
        end = re.sub(r' [+-]\d{4}', '', end)
        
        # Format: "28/Jun/2026:00:03:04 → 28/Jun/2026:00:53:33 | 9"
        print(f"{start} → {end}  |  {count:6}")

# ============================================
# MENU FUNCTIONS
# ============================================
def show_time_menu():
    print(f"\n{Colors.BLUE}═══════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"{Colors.GREEN}⏱️  SELECT TIME FRAME{Colors.NC}")
    print(f"{Colors.BLUE}═══════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"  {Colors.WHITE}1.{Colors.NC} Last 60 minutes")
    print(f"  {Colors.WHITE}2.{Colors.NC} Last 30 minutes")
    print(f"  {Colors.WHITE}3.{Colors.NC} Today (whole day)")
    print(f"  {Colors.WHITE}4.{Colors.NC} Custom time range")
    print(f"  {Colors.WHITE}5.{Colors.NC} Exit")
    print(f"{Colors.BLUE}═══════════════════════════════════════════════════════════════{Colors.NC}")

def show_analysis_menu():
    print(f"\n{Colors.BLUE}═══════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"{Colors.GREEN}🔧 ANALYSIS OPTIONS{Colors.NC}")
    print(f"{Colors.BLUE}═══════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"  {Colors.WHITE}1.{Colors.NC} Top {TOP_COUNT} IP Addresses")
    print(f"  {Colors.WHITE}2.{Colors.NC} Top {TOP_COUNT} User Agents")
    print(f"  {Colors.WHITE}3.{Colors.NC} Top {TOP_COUNT} Requested URLs")
    print(f"  {Colors.WHITE}4.{Colors.NC} Top {TOP_COUNT} Query Strings")
    print(f"  {Colors.WHITE}5.{Colors.NC} HTTP Status Breakdown")
    print(f"  {Colors.WHITE}6.{Colors.NC} Hourly Stats")
    print(f"  {Colors.WHITE}7.{Colors.NC} 📊 Complete Analysis")
    print(f"  {Colors.WHITE}8.{Colors.NC} 📋 Summary Only")
    print(f"  {Colors.WHITE}9.{Colors.NC} 🔙 Back to Time Menu")
    print(f"{Colors.BLUE}═══════════════════════════════════════════════════════════════{Colors.NC}")

# ============================================
# MAIN APPLICATION
# ============================================
def main():
    clear_screen()
    print_header()
    
    print(f"{Colors.CYAN}Enter access log file path:{Colors.NC}")
    print(f"{Colors.YELLOW}Example: /var/log/nginx/access.log{Colors.NC}")
    log_file = input(f"{Colors.WHITE}➜ {Colors.NC}").strip()
    
    if not log_file or not os.path.isfile(log_file):
        print(f"{Colors.RED}❌ File not found: {log_file}{Colors.NC}")
        sys.exit(1)
    
    log_size = os.path.getsize(log_file) / (1024 * 1024)
    timezone = detect_timezone(log_file)
    
    print(f"\n{Colors.GREEN}✓ Log file: {log_file}{Colors.NC}")
    print(f"{Colors.GREEN}✓ Size: {log_size:.2f} MB{Colors.NC}")
    print(f"{Colors.GREEN}✓ Timezone: {timezone}{Colors.NC}")
    
    try:
        with open(log_file, 'r') as f:
            first_line = f.readline()
            f.seek(0, 2)
            pos = f.tell()
            last_line = ""
            while pos > 0:
                pos -= 1
                f.seek(pos)
                if f.read(1) == '\n':
                    last_line = f.readline()
                    break
            if not last_line:
                f.seek(0)
                last_line = f.readlines()[-1] if f else ""
        
        first_ts = get_log_timestamp(first_line) or "Unknown"
        last_ts = get_log_timestamp(last_line) or "Unknown"
        
        print(f"\n{Colors.BLUE}📅 Log Range:{Colors.NC}")
        print(f"  First: {first_ts} → {Colors.CYAN}{convert_to_ist(first_ts)}{Colors.NC}")
        print(f"  Last:  {last_ts} → {Colors.CYAN}{convert_to_ist(last_ts)}{Colors.NC}")
    except Exception as e:
        print(f"\n{Colors.YELLOW}⚠️  Could not read log range: {e}{Colors.NC}")
    
    print(f"\n{Colors.YELLOW}ℹ️  403 status codes are automatically excluded from analysis{Colors.NC}")
    
    parser = None
    current_results = None
    
    while True:
        show_time_menu()
        choice = input(f"{Colors.WHITE}➜ Choose [1-5]: {Colors.NC}").strip()
        if not choice:
            choice = "1"
        
        if choice == "5":
            print(f"\n{Colors.GREEN}🛡️  DDOS Bro! signing off. Stay safe!{Colors.NC}")
            break
        
        now = datetime.now()
        if choice == "1":
            start_time = (now - timedelta(minutes=60)).strftime("[%d/%b/%Y:%H:%M:%S")
            end_time = now.strftime("[%d/%b/%Y:%H:%M:%S")
        elif choice == "2":
            start_time = (now - timedelta(minutes=30)).strftime("[%d/%b/%Y:%H:%M:%S")
            end_time = now.strftime("[%d/%b/%Y:%H:%M:%S")
        elif choice == "3":
            start_time = now.strftime("[%d/%b/%Y:00:00:00")
            end_time = now.strftime("[%d/%b/%Y:23:59:59")
        elif choice == "4":
            print(f"\n{Colors.CYAN}Enter time range (format: YYYY-MM-DD HH:MM:SS){Colors.NC}")
            start_input = input(f"{Colors.WHITE}➜ Start: {Colors.NC}").strip()
            end_input = input(f"{Colors.WHITE}➜ End: {Colors.NC}").strip()
            try:
                start_dt = datetime.strptime(start_input, "%Y-%m-%d %H:%M:%S")
                end_dt = datetime.strptime(end_input, "%Y-%m-%d %H:%M:%S")
                start_time = start_dt.strftime("[%d/%b/%Y:%H:%M:%S")
                end_time = end_dt.strftime("[%d/%b/%Y:%H:%M:%S")
            except ValueError:
                print(f"{Colors.RED}❌ Invalid time format{Colors.NC}")
                continue
        else:
            print(f"{Colors.RED}❌ Invalid choice{Colors.NC}")
            continue
        
        print(f"\n{Colors.CYAN}⏳ Analyzing: {start_time} → {end_time}{Colors.NC}")
        
        parser = LogParser(log_file)
        parser.parse_in_background(start_time, end_time)
        
        if HAS_TQDM:
            with tqdm(total=100, desc="Analyzing logs", bar_format='{l_bar}{bar}| {percentage:3.0f}%') as pbar:
                while parser.is_processing:
                    pbar.n = parser.get_progress()
                    pbar.refresh()
                    time.sleep(0.5)
                pbar.n = 100
                pbar.refresh()
        else:
            while parser.is_processing:
                time.sleep(0.5)
        
        if parser.is_ready():
            current_results = parser.get_results()
        else:
            print(f"{Colors.RED}❌ Failed to parse logs{Colors.NC}")
            continue
        
        if current_results['total_requests'] == 0:
            print(f"\n{Colors.YELLOW}⚠️  No matching entries found in this time range.{Colors.NC}")
            print(f"{Colors.CYAN}Available dates in this log:{Colors.NC}")
            try:
                with open(log_file, 'r') as f:
                    dates = set()
                    for line in f:
                        ts = get_log_timestamp(line)
                        if ts:
                            dates.add(ts.split(':')[0])
                    for date in sorted(dates)[-5:]:
                        print(f"  • {date}")
            except:
                pass
            continue
        
        display_summary(current_results)
        
        while True:
            show_analysis_menu()
            action = input(f"{Colors.WHITE}➜ Choose [1-9]: {Colors.NC}").strip()
            if not action:
                action = "7"
            
            if action == "9":
                break
            
            if action == "1":
                display_top_ips(current_results)
            elif action == "2":
                display_top_ua(current_results)
            elif action == "3":
                display_top_urls(current_results)
            elif action == "4":
                display_top_queries(current_results)
            elif action == "5":
                display_status(current_results)
            elif action == "6":
                display_hourly(current_results)
            elif action == "7":
                display_summary(current_results)
                display_top_ips(current_results)
                display_top_ua(current_results)
                display_top_urls(current_results)
                display_top_queries(current_results)
                display_status(current_results)
                display_hourly(current_results)
            elif action == "8":
                display_summary(current_results)
            else:
                print(f"{Colors.RED}❌ Invalid option{Colors.NC}")
                continue
            
            print(f"\n{Colors.YELLOW}💾 Save results to file? (y/n){Colors.NC}")
            save = input(f"{Colors.WHITE}➜ {Colors.NC}").strip().lower()
            if save in ['y', 'yes']:
                filename = f"ddos_bro_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                with open(filename, 'w') as f:
                    f.write("DDOS Bro! Analysis Report\n")
                    f.write(f"Generated: {datetime.now()}\n")
                    f.write(f"Log File: {log_file}\n")
                    f.write(f"Time Range: {start_time} → {end_time}\n")
                    f.write("=" * 50 + "\n\n")
                    f.write(f"Total Requests: {current_results['total_requests']:,}\n")
                    f.write(f"Total 200 OK: {current_results['total_ok']:,}\n")
                    f.write(f"Total Errors: {current_results['total_errors']:,}\n")
                    f.write(f"403 Excluded: {current_results['total_403']:,}\n")
                print(f"{Colors.GREEN}✅ Results saved to: {filename}{Colors.NC}")
            
            print(f"\n{Colors.YELLOW}🔄 Run another analysis on same time range? (y/n){Colors.NC}")
            again = input(f"{Colors.WHITE}➜ {Colors.NC}").strip().lower()
            if again not in ['y', 'yes']:
                break
    
    print_footer()

# ============================================
# ENTRY POINT
# ============================================
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}⚠️  Interrupted by user{Colors.NC}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}❌ Unexpected error: {e}{Colors.NC}")
        sys.exit(1)
