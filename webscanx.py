"""
webscanx - A comprehensive web scanning tool.

This tool helps users to scan for subdomains, technologies, files, WAFs, and directories in websites.
It utilizes various scanning techniques to gather critical information for security analysis.

Author: sczxw
"""

__version__ = "0.1.1" 

import requests
import dns.resolver
from wafw00f.main import WAFW00F
from colorama import Fore, Style, init
import builtwith
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import os
import re
import socket 
import signal
import sys 

init(autoreset=True)
warnings.filterwarnings("ignore", category=UserWarning)

subdomains_lock = threading.Lock()
directories_lock = threading.Lock()

def signal_handler(sig, frame):
    print(f"\n{Fore.RED}[!] Exiting...{Style.RESET_ALL}")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def print_banner():
    banner = f"""
{Fore.BLUE} __      __      ___.     _________                    ____  ___
{Fore.BLUE}/  \\    /  \\ ____\\_ |__  /   _____/ ____ _____    ____ \\   \\/  /
{Fore.BLUE}\\   \\/\\/   // __ \\| __ \\ \\_____  \\_/ ___\\\\__  \\  /    \\ \\     / 
{Fore.BLUE} \\        /\\  ___/| \\_\\ \\/        \\  \\___ / __ \\|   |  \\/     \\ 
{Fore.BLUE}  \\__/\\  /  \\___  >___  /_______  /\\___  >____  /___|  /___/\\  \\
{Fore.BLUE}       \\/       \\/    \\/        \\/     \\/     \\/     \\/      \\_/
{Fore.MAGENTA}WebScanX - Comprehensive Web Scanning Tool By sczxw. Version {__version__}
{Fore.CYAN}Scan domains for subdomains, technologies, files, WAFs, and directories.
{Fore.BLUE}=========================================={Style.RESET_ALL}
    """
    print(banner)

def validate_domain(domain):
    clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    domain_regex = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    if not domain_regex.match(clean_domain):
        return False
    
    try:
        socket.gethostbyname(clean_domain)
        return True
    except (socket.gaierror, socket.timeout):
        return False

def validate_wordlist_file(file_path):
    if not file_path:  
        return True
    return os.path.isfile(file_path)

def validate_yes_no(input_str):
    return input_str.lower() in ["yes", "no"]

def find_subdomains(domain, wordlist=None):
    subdomains = set()
    wordlist = wordlist or ["www", "mail", "ftp", "test", "api", "dev", "admin", "shop", "assets", "dashboard", "store", "devportal", "cpanel", "backup", "secure", "config", "kubernetes", "vpn", "adminpanel", "files", "auth", "status", "console", "portal", "backup", "management", "control", "db", "internal", "sandbox", "git", "remote", "files", "security", "api-dev", "sysadmin", "firewall", "accounts", "cloud", "wp", "proxy", "developer"]
    def check_subdomain(sub):
        full_domain = f"{sub}.{domain}"
        try:
            try:
                dns.resolver.resolve(full_domain, 'A')
            except dns.resolver.NXDOMAIN:
                return  
            except dns.resolver.NoAnswer:
                return  
            except dns.resolver.Timeout:
                return  

            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }
            try:
                url = f"https://{full_domain}"
                response = requests.get(url, headers=headers, timeout=5)
                if response.status_code in [200, 302, 403, 500]:
                    with subdomains_lock:
                        subdomains.add(full_domain)
            except requests.exceptions.SSLError:
                try:
                    url = f"http://{full_domain}"
                    response = requests.get(url, headers=headers, timeout=5)
                    if response.status_code in [200, 302, 403, 500]:
                        with subdomains_lock:
                            subdomains.add(full_domain)
                except requests.exceptions.RequestException:
                    pass  
            except requests.exceptions.RequestException:
                pass  
        except Exception as e:
            print(f"{Fore.RED}Error checking {full_domain}: {e}{Style.RESET_ALL}")

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_subdomain, sub) for sub in wordlist]
        for future in as_completed(futures):
            future.result() 

    return list(subdomains)

def detect_technologies(url):
    try:
        techs = builtwith.builtwith(url)
        category_map = {
            "web-servers": "Web Servers",
            "programming-languages": "Programming Languages",
            "javascript-frameworks": "JavaScript Frameworks",
            "cms": "Content Management Systems",
            "analytics": "Analytics Tools",
            "caching": "Caching Tools",
            "cdn": "Content Delivery Networks",
            "databases": "Databases",
            "operating-systems": "Operating Systems",
            "security": "Security Tools",
        }
        categorized_technologies = {}
        for category, tech_list in techs.items():
            readable_cat = category_map.get(category, category)
            categorized_technologies[readable_cat] = tech_list
        return categorized_technologies
    except Exception as e:
        print(f"{Fore.RED}Error detecting technologies: {e}{Style.RESET_ALL}")
        return {}

def check_files(url):
    files = ["robots.txt", "security.txt", ".well-known/security.txt"]
    found_files = {}
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    for file in files:
        try:
            full_url = f"{url}/{file}"
            response = requests.get(full_url, headers=headers, timeout=5)
            if response.status_code == 200:
                found_files[file] = f"{Fore.GREEN}Found{Style.RESET_ALL}"
            elif response.status_code == 404:
                found_files[file] = f"{Fore.RED}Not Found{Style.RESET_ALL}"
            else:
                found_files[file] = f"{Fore.YELLOW}Status Code: {response.status_code}{Style.RESET_ALL}"
        except requests.exceptions.SSLError:
            try:
                full_url = f"{url.replace('https://', 'http://')}/{file}"
                response = requests.get(full_url, headers=headers, timeout=5)
                if response.status_code == 200:
                    found_files[file] = f"{Fore.GREEN}Found{Style.RESET_ALL}"
                elif response.status_code == 404:
                    found_files[file] = f"{Fore.RED}Not Found{Style.RESET_ALL}"
                else:
                    found_files[file] = f"{Fore.YELLOW}Status Code: {response.status_code}{Style.RESET_ALL}"
            except requests.exceptions.RequestException as e:
                found_files[file] = f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}"
        except requests.exceptions.RequestException as e:
            found_files[file] = f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}"
    return found_files

def detect_waf(url):
    try:
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"

        waf_detector = WAFW00F(url)
        waf = waf_detector.identwaf()
        if isinstance(waf, tuple):
            if isinstance(waf[0], list) and len(waf[0]) > 0:
                return waf[0][0] 
            else:
                return "Couldn't detect WAF"
        elif isinstance(waf, str):
            return waf  
        else:
            return "Couldn't detect WAF"
    except Exception as e:
        print(f"{Fore.RED}Error detecting WAF: {e}{Style.RESET_ALL}")
        return "Error detecting WAF"

def bruteforce_directories(url, wordlist=None):

    if wordlist is None:
        wordlist = ["admin", "login", "wp-admin", "dashboard", "test", "api", "backup", "config", "assets", "images", "uploads", "status", "api/v1", "api/v2", "status.php", ".index", ".htaccess", "config", "config.php", "private", "secure", "tmp", "scripts", "js", "css", "dev", "db", "login.php", "backup.zip","error.log", "user", "media", "cgi-bin", "contact", "documents"]
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    discovered_dirs = []

    def check_directory(directory):
        full_url = f"{url}/{directory}"
        try:
            response = requests.get(full_url, headers=headers, timeout=5, allow_redirects=False)
            
            if response.status_code == 200:
                with directories_lock:
                    discovered_dirs.append((full_url, "200 OK"))
                    print(f"{Fore.GREEN}  - {full_url}: Found (200 OK){Style.RESET_ALL}")
            elif response.status_code == 403:
                with directories_lock:
                    discovered_dirs.append((full_url, "403 Forbidden"))
                    print(f"{Fore.BLUE}  - {full_url}: 403 Forbidden (Access Denied){Style.RESET_ALL}")
            elif response.status_code == 401:
                with directories_lock:
                    discovered_dirs.append((full_url, "401 Unauthorized"))
                    print(f"{Fore.MAGENTA}  - {full_url}: 401 Unauthorized{Style.RESET_ALL}")
        except requests.exceptions.SSLError:
            try:
                full_url = f"{url.replace('https://', 'http://')}/{directory}"
                response = requests.get(full_url, headers=headers, timeout=5, allow_redirects=False)
                if response.status_code == 200:
                    with directories_lock:
                        discovered_dirs.append((full_url, "200 OK"))
                        print(f"{Fore.GREEN}  - {full_url}: Found (200 OK){Style.RESET_ALL}")
                elif response.status_code == 403:
                    with directories_lock:
                        discovered_dirs.append((full_url, "403 Forbidden"))
                        print(f"{Fore.BLUE}  - {full_url}: 403 Forbidden (Access Denied){Style.RESET_ALL}")
                elif response.status_code == 401:
                    with directories_lock:
                        discovered_dirs.append((full_url, "401 Unauthorized"))
                        print(f"{Fore.MAGENTA}  - {full_url}: 401 Unauthorized{Style.RESET_ALL}")
            except requests.exceptions.RequestException:
                pass
        except requests.exceptions.RequestException:
            pass

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(check_directory, directory) for directory in wordlist]
        for future in as_completed(futures):
            future.result()
    if discovered_dirs:
        print(f"\n{Fore.GREEN}[+] Discovered Directories:{Style.RESET_ALL}")
        for dir_info in discovered_dirs:
            dir_url, status = dir_info
            if "200 OK" in status:
                print(f"{Fore.GREEN}  - {dir_url}: {status}{Style.RESET_ALL}")
            elif "403 Forbidden" in status:
                print(f"{Fore.BLUE}  - {dir_url}: {status}{Style.RESET_ALL}")
            elif "401 Unauthorized" in status:
                print(f"{Fore.MAGENTA}  - {dir_url}: {status}{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.RED}[+] No interesting directories discovered.{Style.RESET_ALL}")

def strip_ansi_codes(text):
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    return ansi_escape.sub("", text)
def save_results(results, filename="results.txt"):
    with open(filename, "w") as f:
        f.write(f"Domain: {results.get('domain', 'N/A')}\n")
        f.write("\n")
        f.write("Subdomains:\n")
        subdomains = results.get("subdomains", [])
        if subdomains:
            for subdomain in subdomains:
                f.write(f"  - {subdomain}\n")
        else:
            f.write("  No subdomains found.\n")
        f.write("\n")
        f.write("Technologies:\n")
        technologies = results.get("technologies", {})
        if technologies:
            for category, tech_list in technologies.items():
                f.write(f"{category}:\n")
                for tech in tech_list:
                    f.write(f"  - {strip_ansi_codes(tech)}\n")  
        else:
            f.write("  No technologies detected.\n")
        f.write("\n")
        f.write("Files:\n")
        files = results.get("files", {})
        if files:
            for file, status in files.items():
                f.write(f"  - {file}: {strip_ansi_codes(status)}\n")  
        else:
            f.write("  No files found.\n")
        f.write("\n")
        f.write("WAF:\n")
        waf = results.get("waf", "N/A")
        f.write(f"  - {strip_ansi_codes(waf)}\n")  
        f.write("\n")
    print(f"\n{Fore.CYAN}[+] Results saved to {filename}{Style.RESET_ALL}")

def main():
    print_banner()

    while True:
        domain_input = input(f"{Fore.YELLOW}Enter the domain to scan (e.g., example.com): {Style.RESET_ALL}").strip()
        if not domain_input:
            continue
        if not domain_input.startswith(('http://', 'https://')):
            domain = f"https://{domain_input}"
        else:
            domain = domain_input
        clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

        if not validate_domain(clean_domain):
            print(f"{Fore.RED}Error: Domain '{clean_domain}' is invalid or doesn't resolve.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Please check:")
            print(f"1. The domain spelling")
            print(f"2. Your internet connection")
            print(f"3. Try again with a known-working domain like 'example.com'{Style.RESET_ALL}")
            continue
        else:
            print(f"{Fore.GREEN}[+] Domain '{clean_domain}' is valid and resolves.{Style.RESET_ALL}")
            break
    while True:
        wordlist_file = input(f"{Fore.YELLOW}Enter the path to a custom wordlist file for subdomains (or press Enter to use the default): {Style.RESET_ALL}").strip()
        if validate_wordlist_file(wordlist_file):
            break
        else:
            print(f"{Fore.RED}Invalid Input: Wordlist file not found. Please provide a valid file path.{Style.RESET_ALL}")
    wordlist = None
    if wordlist_file:
        try:
            with open(wordlist_file, "r") as f:
                wordlist = [line.strip() for line in f if line.strip()]
            print(f"{Fore.GREEN}[+] Using custom wordlist: {wordlist_file}{Style.RESET_ALL}")
        except FileNotFoundError:
            print(f"{Fore.RED}Error: Wordlist file not found. Using default wordlist.{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}[+] Using default wordlist for subdomains.{Style.RESET_ALL}")
    while True:
        dir_wordlist_file = input(f"{Fore.YELLOW}Enter the path to a custom wordlist file for directory bruteforcing (or press Enter to use the default): {Style.RESET_ALL}").strip()
        if validate_wordlist_file(dir_wordlist_file):
            break
        else:
            print(f"{Fore.RED}Invalid Input: Wordlist file not found. Please provide a valid file path.{Style.RESET_ALL}")

    dir_wordlist = None
    if dir_wordlist_file:
        try:
            with open(dir_wordlist_file, "r") as f:
                dir_wordlist = [line.strip() for line in f if line.strip()]
            print(f"{Fore.GREEN}[+] Using custom wordlist for directory bruteforcing: {dir_wordlist_file}{Style.RESET_ALL}")
        except FileNotFoundError:
            print(f"{Fore.RED}Error: Wordlist file not found. Using default wordlist for directory bruteforcing.{Style.RESET_ALL}")

    else:
        print(f"{Fore.GREEN}[+] Using default wordlist for directory bruteforcing.{Style.RESET_ALL}")
    if not domain.startswith(('http://', 'https://')):
        url = f"https://{domain}" 
    else:
        url = domain
    print(f"\n{Fore.CYAN}[+] Scanning domain: {url}{Style.RESET_ALL}")

    print(f"\n{Fore.BLUE}[+] Finding subdomains...{Style.RESET_ALL}")
    subdomains = find_subdomains(clean_domain, wordlist)
    if subdomains:
        print(f"{Fore.GREEN}Subdomains found: {Style.RESET_ALL}{subdomains}")
    else:
        print(f"{Fore.RED}No subdomains found.{Style.RESET_ALL}")

    print(f"\n{Fore.BLUE}[+] Detecting web technologies...{Style.RESET_ALL}")
    technologies = detect_technologies(url)
    if technologies:
        for category, tech_list in technologies.items():
            print(f"{Fore.GREEN}{category}: {Style.RESET_ALL}")
            for tech in tech_list:
                print(f"  - {tech}")
    else:
        print(f"{Fore.RED}No technologies detected.{Style.RESET_ALL}")
    print(f"\n{Fore.BLUE}[+] Checking for important files...{Style.RESET_ALL}")
    files = check_files(url)
    for file, status in files.items():
        print(f"{Fore.YELLOW}{file}: {Style.RESET_ALL}{status}")

    print(f"\n{Fore.BLUE}[+] Detecting WAF...{Style.RESET_ALL}")
    waf = detect_waf(url)
    print(f"{Fore.GREEN}WAF detected: {Style.RESET_ALL}{waf}")
    print(f"\n{Fore.BLUE}[+] Bruteforcing directories...{Style.RESET_ALL}")
    bruteforce_directories(url, dir_wordlist)

    while True:
        save_option = input(f"{Fore.YELLOW}Do you want to save the results to a file? (yes/no): {Style.RESET_ALL}").strip().lower()
        if validate_yes_no(save_option):
            break
        else:
            print(f"{Fore.RED}Invalid Input: Please enter 'yes' or 'no'.{Style.RESET_ALL}")
    if save_option == "yes":
        filename = input(f"{Fore.YELLOW}Enter the name of the results file (e.g., output.txt, or press Enter for default): {Style.RESET_ALL}").strip()
        if not filename:
            filename = "results.txt"  
        results = {
            "domain": domain,
            "subdomains": subdomains,
            "technologies": technologies,
            "files": files,
            "waf": waf
        }
        save_results(results, filename)
    else:
        print(f"{Fore.CYAN}[+] Results not saved.{Style.RESET_ALL}")
if __name__ == "__main__":

    main()
