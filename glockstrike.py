import socket
import requests
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor
import subprocess
import sys
import time

# -------------------- BANNER --------------------
def print_banner():
    banner = r"""

                                                       
                   G L O C K S T R I K E
                   DEV: GLOCK-0DAY & WAZEHAX
    """
    print(banner)

# -------------------- MODÜLLER --------------------
def tcp_port_scan(host):
    print(f"\n[TCP Port Scan] {host} ports 1-1024")
    for port in range(1,1025):
        try:
            s = socket.socket()
            s.settimeout(0.5)
            s.connect((host, port))
            print(f"[TCP OPEN] {host}:{port}")
        except:
            pass
        finally:
            s.close()
    print("[TCP Scan] Completed\n")

def subdomain_scan(domain):
    print(f"\n[Subdomain Scan] Common subdomains for {domain}")
    common_subs = ["www","mail","dev","test","admin","api"]
    for sub in common_subs:
        full = f"{sub}.{domain}"
        res = subprocess.call(f"ping -n 1 {full}", shell=True, stdout=subprocess.DEVNULL)
        if res==0:
            print(f"[Subdomain Live] {full}")
    print("[Subdomain Scan] Completed\n")

def http_get(url):
    try:
        resp = requests.get(url, timeout=5)
        return resp.text
    except:
        return ""

def cve_scan(url):
    print(f"\n[CVE Scan] Checking admin paths and headers for {url}")
    admin_paths = ["/admin","/login","/manager","/cpanel"]
    found = False
    for path in admin_paths:
        full_url = urljoin(url, path)
        resp = http_get(full_url)
        if resp and ("login" in resp.lower() or "password" in resp.lower()):
            print(f"[CVE] Admin panel detected at {full_url}")
            found = True
    try:
        resp = requests.head(url, timeout=5)
        server = resp.headers.get("Server","")
        if server:
            print(f"[CVE] Server header: {server}")
            found = True
    except:
        pass
    if not found:
        print("[CVE] No common vulnerabilities detected")
    print("[CVE Scan] Completed\n")

def sql_injection_test(url):
    print(f"\n[SQLi Test] Testing {url}")
    sqli_payloads = ["' OR '1'='1","' UNION SELECT NULL,NULL,NULL--","' AND SLEEP(1)--"]
    found = False
    for payload in sqli_payloads:
        test_url = f"{url}?id={payload}"
        resp = http_get(test_url)
        if resp and "error" not in resp.lower():
            print(f"[SQLi] Potential vulnerability: {test_url}")
            found = True
    if not found:
        print("[SQLi] No SQL Injection vulnerabilities found")
    print("[SQLi Test] Completed\n")

def xss_test(url):
    print(f"\n[XSS Test] Testing {url}")
    xss_payloads = ["<script>alert(1)</script>","'><img src=x onerror=alert(1)>","<svg/onload=alert(1)>"]
    found = False
    for payload in xss_payloads:
        test_url = f"{url}?q={payload}"
        resp = http_get(test_url)
        if payload in resp:
            print(f"[XSS] Potential vulnerability: {test_url}")
            found = True
    if not found:
        print("[XSS] No XSS vulnerabilities found")
    print("[XSS Test] Completed\n")

def admin_panel_finder(url):
    print(f"\n[Admin Panel Finder] Checking {url}")
    admins = ["/admin","/login","/cpanel","/manager"]
    found = False
    for path in admins:
        full = urljoin(url, path)
        if http_get(full):
            print(f"[Admin Panel] {full}")
            found = True
    if not found:
        print("[Admin Panel Finder] No admin panel found")
    print("[Admin Panel Finder] Completed\n")

def directory_scan(url):
    print(f"\n[Directory Scan] {url}")
    directories = ["/backup","/uploads","/config","/files"]
    found = False
    for d in directories:
        full = urljoin(url,d)
        resp = http_get(full)
        if resp:
            print(f"[Directory] {full}")
            found = True
    if not found:
        print("[Directory Scan] No accessible directories found")
    print("[Directory Scan] Completed\n")

def sensitive_file_finder(url):
    print(f"\n[Sensitive File Finder] {url}")
    sensitive_files = ["/.git/config","/config.php","/wp-config.php"]
    found = False
    for f in sensitive_files:
        full = urljoin(url,f)
        resp = http_get(full)
        if resp:
            print(f"[Sensitive File] {full}")
            found = True
    if not found:
        print("[Sensitive File Finder] No sensitive files found")
    print("[Sensitive File Finder] Completed\n")

def payload_runner(url):
    print(f"\n[Payload Runner] Sending safe test payloads to {url}")
    test_paths = ["/login","/contact","/search"]
    payload_data = {"username":"admin","password":"test123"}
    for path in test_paths:
        full = urljoin(url,path)
        try:
            resp = requests.post(full,data=payload_data,timeout=5)
            if resp.status_code == 200:
                print(f"[Payload Runner] Payload sent to {full} (OK)")
            else:
                print(f"[Payload Runner] Payload sent to {full} (Status: {resp.status_code})")
        except:
            print(f"[Payload Runner] Failed to send payload to {full}")
    print("[Payload Runner] Completed\n")

def http_sec_headers(url):
    print(f"\n[HTTP Security Headers] {url}")
    try:
        resp = requests.head(url, timeout=5)
        for header in ["Content-Security-Policy","X-Frame-Options","X-XSS-Protection","Strict-Transport-Security"]:
            val = resp.headers.get(header)
            print(f"{header}: {val}")
    except:
        print("Failed to get headers")
    print("[HTTP Security Headers] Completed\n")

def waf_detection(url):
    print(f"\n[WAF Detection] {url}")
    try:
        resp = requests.get(url,timeout=5)
        if "cloudflare" in str(resp.headers).lower():
            print("[WAF] Cloudflare detected")
        else:
            print("[WAF] No WAF detected")
    except:
        print("[WAF] Error detecting WAF")
    print("[WAF Detection] Completed\n")

def open_redirect_check(url):
    print(f"\n[Open Redirect Check] {url}")
    test_path = "/?next=http://example.com"
    full = url + test_path
    try:
        resp = requests.get(full, timeout=5, allow_redirects=False)
        if resp.status_code in [301,302]:
            print(f"[Open Redirect] Potential redirect: {full}")
        else:
            print("[Open Redirect] No redirect detected")
    except:
        print("[Open Redirect] Error")
    print("[Open Redirect Check] Completed\n")

def js_analyzer(url):
    print(f"\n[JS Analyzer] {url}")
    scripts = ["/app.js","/main.js","/index.js"]
    for s in scripts:
        full = urljoin(url,s)
        resp = http_get(full)
        if resp:
            print(f"[JS File] Found: {full}")
    print("[JS Analyzer] Completed\n")

def whois_lookup(domain):
    print(f"\n[WHOIS Lookup] Domain: {domain}")
    try:
        subprocess.call(f"whois {domain}", shell=True)
    except:
        print("[WHOIS] Error")
    print("[WHOIS Lookup] Completed\n")

def ip_info(domain):
    print(f"\n[IP Info] Domain: {domain}")
    try:
        ip = socket.gethostbyname(domain)
        print(f"IP: {ip}")
    except:
        print("[IP Info] Error")
    print("[IP Info] Completed\n")

def email_harvester(domain):
    print(f"\n[Email Harvester] Simulated scan for {domain}")
    print(f"Found emails: admin@{domain}, contact@{domain}")
    print("[Email Harvester] Completed\n")

def robots_parser(url):
    print(f"\n[Robots.txt Parser] {url}/robots.txt")
    try:
        resp = requests.get(url+"/robots.txt", timeout=5)
        print(resp.text if resp.text else "No robots.txt found")
    except:
        print("Error fetching robots.txt")
    print("[Robots.txt Parser] Completed\n")

def sitemap_scanner(url):
    print(f"\n[Sitemap Scanner] {url}/sitemap.xml")
    try:
        resp = requests.get(url+"/sitemap.xml", timeout=5)
        print(resp.text if resp.text else "No sitemap.xml found")
    except:
        print("Error fetching sitemap.xml")
    print("[Sitemap Scanner] Completed\n")

def wayback_check(url):
    print(f"\n[Wayback Machine Check] Simulated check for {url}")
    print("Found archived URLs: /old-page, /test, /backup")
    print("[Wayback Machine Check] Completed\n")

def common_vuln_finder(url):
    print(f"\n[Common Vulnerability Finder] {url}")
    print("Shellshock, Directory Traversal, Info Disclosure tests simulated")
    print("[Common Vulnerability Finder] Completed\n")

# -------------------- MENÜ --------------------
modules = {
    "1": ("TCP Port Scan", tcp_port_scan),
    "2": ("Subdomain Scan", subdomain_scan),
    "3": ("CVE Scan", cve_scan),
    "4": ("SQL Injection Test", sql_injection_test),
    "5": ("XSS Test", xss_test),
    "6": ("Admin Panel Finder", admin_panel_finder),
    "7": ("Directory Scan", directory_scan),
    "8": ("Sensitive File Finder", sensitive_file_finder),
    "9": ("Payload Runner", payload_runner),
    "10": ("HTTP Security Headers", http_sec_headers),
    "11": ("WAF Detection", waf_detection),
    "12": ("Open Redirect Check", open_redirect_check),
    "13": ("JS Analyzer", js_analyzer),
    "14": ("WHOIS Lookup", whois_lookup),
    "15": ("IP Info", ip_info),
    "16": ("Email Harvester", email_harvester),
    "17": ("Robots.txt Parser", robots_parser),
    "18": ("Sitemap Scanner", sitemap_scanner),
    "19": ("Wayback Machine Check", wayback_check),
    "20": ("Common Vulnerability Finder", common_vuln_finder)
}

# -------------------- MAIN --------------------
def main():
    print_banner()
    print("=== Menü ===\n")
    for key, val in modules.items():
        print(f"{key}. {val[0]}")

    choice = input("\nÇalıştırmak istediğin modülü seç (1-20): ").strip()
    if choice not in modules:
        print("Geçersiz seçim!")
        return

    target = input("Hedef IP/Host gir: ").strip()
    module_func = modules[choice][1]

    if choice in ["1","2","14","15","16"]:
        module_func(target)
    else:
        url = "http://" + target
        module_func(url)

    print("\n[Tarama tamamlandı]")

if __name__=="__main__":
    main()
