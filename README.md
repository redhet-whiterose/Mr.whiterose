# Mr.whiterose
The tool is fully automated, real-time interactive, and optimized for bug bounty, CTF, and red team reconnaissance scenarios. It uses a modular architecture with clean CLI outputs powered by the rich library.

# 🚨 FuzzCollector v2.1 — XSS & HTML Injection Vulnerability Scanner

<p align="center">
  <img src="https://img.shields.io/badge/python-3.6%2B-blue" />
  <img src="https://img.shields.io/badge/status-active-success" />
  <img src="https://img.shields.io/badge/UI-rich-brightgreen" />
</p>

---

## 🧠 About

**FuzzCollector** is an all-in-one subdomain recon and web vulnerability scanner focused on discovering:

- 🔍 **Live subdomains** (via wordlist fuzzing)
- 🛰️ **Historical endpoints** (via Wayback Machine)
- 💉 **Reflected XSS** vulnerabilities
- 🧬 **HTML injection** points (custom HTML tag injections)

All vulnerabilities are detected **live** and shown in a beautiful `rich`-powered terminal interface — and saved to log files for later triage.

---

## 🚀 Features

✅ Fast subdomain discovery  
✅ Wayback Machine endpoint harvesting  
✅ Parameterized URL filtering  
✅ Reflected XSS detection  
✅ HTML injection detection  
✅ Custom payloads  
✅ Beautiful terminal UI (`rich`)  
✅ Clean Ctrl+C exit  
✅ Saves results to output folder  

---

## 📸 Demo

```bash
┌──────────────────────────────┐
│ FuzzCollector v2.1 🧪        │
│ Target: testphp.vulnweb.com │
└──────────────────────────────┘

🔍 Fuzzing subdomains...
[+] Alive: admin.testphp.vulnweb.com

🛰️ Collecting endpoints...
[+] Found 31 URLs from Wayback

💉 Scanning for XSS & HTMLi...

[XSS] found:  https://target.com/page?id=<script>alert(1337)</script>
[HTML] found: https://target.com/page?x=</a><a href="https://bing.com">click</a>

✔ Results saved to: output/xss_html_results.txt
