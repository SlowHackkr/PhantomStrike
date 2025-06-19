# phantomstrike.py
# Complete Multi-Phase Red Team Recon & Attack Framework

import socket
import requests
import re
import base64
import json
import argparse
import time
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

# -- Hacker Faces & Phase Art --
def show_banner():
    print(r'''
\033[1;31m   ________  __    __   _______   ______   .___  ___.  _______ .___________. _______
  /  _____||  |  |  | |   ____| /  __  \  |   \/   | |   ____||           ||   ____|
 |  |  __  |  |  |  | |  |__   |  |  |  | |  \  /  | |  |__   `---|  |----`|  |__
 |  | |_ | |  |  |  | |   __|  |  |  |  | |  |\/|  | |   __|      |  |     |   __|
 |  |__| | |  `--'  | |  |____ |  `--'  | |  |  |  | |  |____     |  |     |  |____
  \______|  \______/  |_______| \______/  |__|  |__| |_______|    |__|     |_______|

                \033[1;33mPHANTOMSTRIKE: From Surface to Shadows [Red Team Edition]\033[0m
''')


def phase_art(phase_num, title):
    faces = [
        r"(\_/)", r"(ಠ_ಠ)", r"(⌐■_■)", r"(╯□ツ□）╯", r"(ง◕□◕)ง", r"ಠ_ಠ",
        r"(='X'=)", r"(>_<)", r"(\"◕_◕\")", r"(╯°□°)╯", r"(¬_¬)", r"(☠_☠)",
        r"(☁️_☁️)", r"(🕷_🕷)", r"(🧬_🧬)"
    ]
    print(f"\n\033[1;36m[PHASE {phase_num}] {title} \033[0m{faces[(phase_num-1)%len(faces)]}")
    print("\033[2;37m" + "="*70 + "\033[0m")


# -- Phase 1: Network Recon --
def phase1_network_scan(target):
    phase_art(1, "Basic Network Scanning")
    try:
        ip = socket.gethostbyname(target)
        print(f"[+] Host resolved: {target} -> {ip}")
        ports = [80, 443, 21, 22, 8080]
        for port in ports:
            s = socket.socket()
            s.settimeout(1)
            try:
                s.connect((ip, port))
                print(f"[+] Port {port} open")
                s.close()
            except:
                pass
    except Exception as e:
        print(f"[!] Network error: {e}")

# -- Phase 2: Passive Recon --
def phase2_passive_recon(html):
    phase_art(2, "Passive Recon & Email Leakage")
    emails = re.findall(r"[\w.-]+@[\w.-]+", html)
    for email in set(emails):
        print(f"[+] Email found: {email}")

# -- Phase 3: Firebase / Secrets / JS Enum --
def phase3_cloud_firebase(js_urls):
    phase_art(3, "Firebase Key & Cloud Secrets")
    firebase_pat = r'Ai...{35}'
    for js in js_urls:
        try:
            text = requests.get(js).text
            for match in re.findall(firebase_pat, text):
                print(f"[+] Firebase API Key: {match}")
        except: continue

# -- Phase 4: Cookie Audit --
def phase4_cookie_flags(url):
    phase_art(4, "Cookie Flag Inspection")
    try:
        r = requests.get(url)
        for c in r.cookies:
            print(f"[!] Cookie: {c.name}, Secure={c.secure}, HttpOnly={c.has_nonstandard_attr('HttpOnly')}")
    except Exception as e:
        print(f"[!] Cookie error: {e}")

# -- Phase 5: SSRF Fuzzing --
def phase5_ssrf(url):
    phase_art(5, "SSRF Fuzzing & Local Targeting")
    ssrf_payloads = ['http://127.0.0.1', 'http://localhost', 'http://169.254.169.254']
    for p in ssrf_payloads:
        try:
            r = requests.get(f"{url}?url={p}", timeout=5)
            print(f"[?] SSRF test {p} => {r.status_code}")
        except: pass

# -- Phase 6: JS File Scan & Endpoints --
def phase6_js_scan(js_urls):
    phase_art(6, "JS Endpoint Recon")
    url_pattern = r'https?://[\w./?=-]+'
    for js in js_urls:
        try:
            content = requests.get(js, timeout=5).text
            for url in re.findall(url_pattern, content):
                print(f"[>] JS Endpoint: {url}")
        except: pass

# -- Phase 7: JWT Decode --
def phase7_jwt_decode(token):
    phase_art(7, "JWT Decoding & Inspection")
    try:
        header, payload, _ = token.split('.')
        print("[JWT] Header:", json.loads(base64.urlsafe_b64decode(header + '==')))
        print("[JWT] Payload:", json.loads(base64.urlsafe_b64decode(payload + '==')))
    except:
        print("[!] Invalid JWT format")

# -- Phase 8: OAuth Redirect Test --
def phase8_redirect_check(url):
    phase_art(8, "OAuth Redirect Vulnerability Test")
    test = url + "?url=https://evil.com"
    try:
        r = requests.get(test, allow_redirects=False)
        if 'evil.com' in r.headers.get('Location', ''):
            print(f"[!] Possible Open Redirect: {test}")
        else:
            print("[+] Redirect seems safe")
    except: pass

# -- Phase 9: Subdomain & Bucket Leaks --
def phase9_bucket_and_sub(url):
    phase_art(9, "Subdomain Takeover & Cloud Bucket Leak")
    if 'firebaseio.com' in url or 'storage.googleapis.com' in url:
        print("[+] Firebase storage reference detected!")

# -- Phase 10: OAuth Fuzzing Stub --
def phase10_future():
    phase_art(10, "(Stub) Advanced PKCE/OAuth Fuzzing")
    print("[*] Future fuzzing modules will go here (PKCE, scope escalation, confusion tests)")

# -- Phase 11: JWT Algo Confusion --
def phase11_jwt_confusion():
    phase_art(11, "JWT Algo Confusion + Kid Injection")
    print("[*] This phase will attempt to check for alg:none and kid header attacks")
    print("[*] (Stub) Add JWT signing key confusion, tamperable kid logic here")

# -- Phase 12: DOM XSS / CSP Checker --
def phase12_dom_xss_csp(html):
    phase_art(12, "DOM XSS / CSP Bypass Checker")
    if 'Content-Security-Policy' not in html:
        print("[!] No CSP header found — possible XSS risk")
    dom_xss_patterns = ["document.write", "innerHTML", "location.href"]
    for pattern in dom_xss_patterns:
        if pattern in html:
            print(f"[!] Possible DOM sink: {pattern}")

# -- Phase 13: Cloud Role Abuse --
def phase13_cloud_roles():
    phase_art(13, "GCP/AWS/Azure Role Abuse Scanner")
    print("[*] (Stub) This would detect open roles, misconfigured IAM policies, etc.")

# -- Phase 14: Passive Proxy --
def phase14_passive_proxy():
    phase_art(14, "Burp-compatible Passive Proxy")
    print("[*] (Stub) Hook this to MITM server for live recon via browser/Burp")

# -- Phase 15: Wordlist Gen --
def phase15_custom_wordlist(html, js_urls):
    phase_art(15, "Custom Wordlist Generator (from JS/HTML)")
    words = set(re.findall(r"[a-zA-Z0-9_]{6,}", html))
    for js in js_urls:
        try:
            content = requests.get(js, timeout=5).text
            words.update(re.findall(r"[a-zA-Z0-9_]{6,}", content))
        except: continue
    print("[+] Generated Wordlist Candidates:")
    for w in sorted(words):
        print(f" - {w}")

# -- JS Link Extractor --
def extract_js_links(html, base):
    soup = BeautifulSoup(html, 'html.parser')
    return [urljoin(base, tag['src']) for tag in soup.find_all('script', src=True)]

# -- Main Function --
def main():
    show_banner()
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', required=True, help='Target URL to analyze')
    parser.add_argument('--jwt', help='Optional JWT for decoding')
    args = parser.parse_args()

    parsed = urlparse(args.target)
    domain = parsed.netloc or parsed.path.split('/')[0]
    phase1_network_scan(domain)

    try:
        res = requests.get(args.target)
        html = res.text
    except:
        print("[!] Could not fetch target page")
        return

    js_urls = extract_js_links(html, args.target)

    phase2_passive_recon(html)
    phase3_cloud_firebase(js_urls)
    phase4_cookie_flags(args.target)
    phase5_ssrf(args.target)
    phase6_js_scan(js_urls)

    if args.jwt:
        phase7_jwt_decode(args.jwt)

    phase8_redirect_check(args.target)
    phase9_bucket_and_sub(args.target)
    phase10_future()
    phase11_jwt_confusion()
    phase12_dom_xss_csp(html)
    phase13_cloud_roles()
    phase14_passive_proxy()
    phase15_custom_wordlist(html, js_urls)

    print("\n\033[1;32m[✔] PhantomStrike: All 15 phases completed. Continue your hunt.\033[0m")

if __name__ == '__main__':
    main()
