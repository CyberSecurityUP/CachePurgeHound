import subprocess
import json
from tqdm import tqdm

def run_subfinder(domain):
    result = subprocess.run(['subfinder', '-d', domain, '-silent'], capture_output=True, text=True)
    return result.stdout.strip().split('\n')

def run_httpx(subdomains):
    result = subprocess.run(['httpx', '-silent', '-status-code', '-mc', '200'], input="\n".join(subdomains), text=True, capture_output=True)
    return [line.split()[0] for line in result.stdout.strip().split('\n') if line]

def check_x_cache_header(url):
    result = subprocess.run(['curl', '--head', '-s', url], capture_output=True, text=True)
    return 'x-cache' in result.stdout.lower()

def try_purge(url):
    result = subprocess.run(['curl', '-s', '-X', 'PURGE', url], capture_output=True, text=True)
    try:
        data = json.loads(result.stdout)
        return data.get('status') == 'ok'
    except json.JSONDecodeError:
        return False

def main():
    domain = input("Enter the target domain (e.g. example.com): ").strip()
    
    print("[*] Running subfinder...")
    subdomains = run_subfinder(domain)
    
    print(f"[*] Found {len(subdomains)} subdomains.")
    
    print("[*] Checking live subdomains using httpx...")
    live_subs = run_httpx(subdomains)
    
    print(f"[*] {len(live_subs)} live subdomains.")
    
    print("[*] Scanning for Unauthenticated Cache Purging vulnerability...\n")
    for sub in tqdm(live_subs):
        if check_x_cache_header(sub):
            if try_purge(sub):
                print(f"[VULNERABLE] {sub} accepts unauthenticated PURGE requests!")
            else:
                print(f"[!] {sub} has x-cache but did not return OK to PURGE.")
        else:
            print(f"[-] {sub} does not include x-cache header.")
    
    print("\n[+] Scan complete.")

if __name__ == "__main__":
    main()
