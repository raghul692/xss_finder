# XSS Finder — Professional XSS Vulnerability Scanner

```
 ██╗  ██╗███████╗███████╗    ███████╗██╗███╗   ██╗██████╗ ███████╗██████╗ 
 ╚██╗██╔╝██╔════╝██╔════╝    ██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
  ╚███╔╝ ███████╗███████╗    █████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
  ██╔██╗ ╚════██║╚════██║    ██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
 ██╔╝ ██╗███████║███████║    ██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║
 ╚═╝  ╚═╝╚══════╝╚══════╝    ╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
```

> **FOR AUTHORIZED PENETRATION TESTING AND SECURITY RESEARCH ONLY.**
> Never use this tool on systems you do not own or have explicit written permission to test.

---

## 📌 What is XSS Finder?

XSS Finder is a Python-based CLI tool for detecting **Cross-Site Scripting (XSS)** vulnerabilities in web applications. It:

- 🕷️ Crawls target websites to discover all pages, forms, and parameters
- 💉 Injects a comprehensive library of XSS payloads
- 🔍 Detects Reflected, Stored, and DOM-based XSS
- 📊 Generates professional JSON and TXT reports
- 🎨 Provides real-time colored terminal output

---

## 📁 Project Structure

```
xss_finder/
│
├── main.py                     ← CLI entry point (argparse)
├── payloads.txt                ← XSS payload library (categorized)
├── requirements.txt            ← Python dependencies
├── README.md                   ← This file
│
├── scanner/
│   ├── __init__.py
│   ├── engine.py               ← Main scan orchestrator
│   ├── crawler.py              ← Web crawler (link/form/param discovery)
│   ├── payload_manager.py      ← Payload loading and filtering
│   ├── injector.py             ← HTTP GET/POST injection engine
│   ├── detector.py             ← XSS detection (reflection + context)
│   └── analyzer.py             ← False positive reduction
│
├── reports/
│   ├── __init__.py
│   └── report_generator.py    ← JSON and TXT report generation
│
└── utils/
    ├── __init__.py
    ├── logger.py               ← Colored terminal logger
    └── helpers.py              ← URL/cookie/header utilities
```

---

## ⚙️ Installation

### Step 1: Clone or extract the project

```bash
# If using zip
unzip xss_finder.zip
cd xss_finder
```

### Step 2: Create a virtual environment (recommended)

```bash
python3 -m venv venv
source venv/bin/activate          # Linux/Mac
# OR
venv\Scripts\activate             # Windows
```

### Step 3: Install dependencies

```bash
pip install -r requirements.txt
```

---

## 🚀 Usage

### Basic scan
```bash
python main.py --url http://testphp.vulnweb.com
```

### Crawl 3 levels deep
```bash
python main.py --url http://testphp.vulnweb.com --crawl-depth 3
```

### Use only advanced payloads
```bash
python main.py --url http://example.com --payload-type advanced
```

### Save reports
```bash
python main.py --url http://example.com --output results
# Creates: results.json + results.txt
```

### Single URL (no crawling)
```bash
python main.py --url "http://example.com/search?q=test" --no-crawl
```

### With cookies (authenticated scan)
```bash
python main.py --url http://example.com --cookies "session=abc123; csrftoken=xyz"
```

### Verbose mode (show all debug info)
```bash
python main.py --url http://example.com --verbose
```

### Full options scan
```bash
python main.py \
  --url http://testphp.vulnweb.com \
  --crawl-depth 3 \
  --payload-type all \
  --threads 5 \
  --timeout 15 \
  --delay 0.3 \
  --output scan_report \
  --format both \
  --verbose

 python main.py  --url  https://www.ilovepdf.com/
 
 python main.py --url https://claude.ai/

  
  python main.py  --url https://gemini.google.com/  --crawl-depth 3 --payload-type all --threads 5 --timeout 15  --delay 0.3 --output scan_report --format both  --verbose
```

---

## 📋 All CLI Options

| Option | Default | Description |
|---|---|---|
| `--url` | Required | Target URL to scan |
| `--crawl-depth N` | 2 | How deep to crawl links |
| `--no-crawl` | - | Disable crawling, single URL only |
| `--payloads FILE` | payloads.txt | Path to payload file |
| `--payload-type` | all | basic / advanced / waf_bypass / dom / all |
| `--output FILE` | auto | Base filename for reports |
| `--format` | both | json / txt / both |
| `--threads N` | 3 | Concurrent threads |
| `--timeout SEC` | 10 | Request timeout |
| `--delay SEC` | 0.5 | Delay between requests |
| `--cookies STRING` | - | Cookie string (e.g. "sess=abc") |
| `--headers JSON` | - | Extra headers as JSON |
| `--user-agent UA` | - | Custom User-Agent |
| `--verbose / -v` | - | Show debug output |
| `--dom-check` | - | DOM XSS detection (needs Selenium) |

---

## 🧠 How Detection Works

### Phase 1 — Information Gathering
The crawler starts at the target URL and recursively visits all links within the same domain up to the specified depth. For each page, it extracts:
- **URL parameters** (GET-based injection points)
- **HTML forms** (input, textarea, select elements with their action URLs and methods)

### Phase 2 — Payload Preparation  
The PayloadManager loads `payloads.txt` and categorizes payloads into:
- `[BASIC]` — Standard `<script>alert(1)</script>` style payloads
- `[ADVANCED]` — Polyglots, HTML5, attribute-breaking payloads
- `[WAF_BYPASS]` — Case variations, encoding, comment insertion
- `[DOM]` — DOM sink exploitation payloads

### Phase 3 — Active Injection
The Injector fires HTTP GET and POST requests with payloads substituted into each parameter/field. The Detector then:
1. Checks if the exact payload appears in the response (reflection check)
2. Verifies dangerous characters are NOT HTML-encoded (encoding check)
3. Identifies where in the HTML the payload landed (context: script/attribute/html)
4. Assigns confidence level (High/Medium/Low) based on execution patterns

The Analyzer runs a secondary validation:
- Confirms response is HTML
- Detects WAF blocking
- Verifies payload structure is intact
- Checks if payload is in an executable position

### Phase 4 — Reporting
Reports are sorted by severity and written to JSON and/or TXT files.

---

## 🎯 Sample Output

```
  ── SCAN CONFIGURATION ──────────────────────────────────────────────
  [*] Target URL    : http://testphp.vulnweb.com
  [*] Crawl Depth   : 2
  [*] Payload File  : payloads.txt
  [*] Payload Type  : ALL

  ─────────────────────────────────────────────────────────────────────
    PHASE 1 — INFORMATION GATHERING
  ─────────────────────────────────────────────────────────────────────
  [+] http://testphp.vulnweb.com/search.php  (Forms: 1, Params: 0)
  [+] http://testphp.vulnweb.com/listproducts.php?cat=1  (Forms: 0, Params: 1)
  [*] Crawl complete | Pages visited: 12 | Injectable targets: 5

  ─────────────────────────────────────────────────────────────────────
    PHASE 3 — ACTIVE VULNERABILITY SCANNING
  ─────────────────────────────────────────────────────────────────────
  [1/5] → http://testphp.vulnweb.com/search.php

  ─────────────────────────────────────────────────────────────────────
  [!!!] VULNERABILITY FOUND
  ─────────────────────────────────────────────────────────────────────
  Type        : Reflected XSS
  Severity    : High
  URL         : http://testphp.vulnweb.com/search.php
  Method      : GET
  Parameter   : searchFor
  Context     : HTML
  Confidence  : High
  Payload     : <script>alert(1)</script>
  PoC         : curl -s 'http://testphp.vulnweb.com/search.php?searchFor=...'
  ─────────────────────────────────────────────────────────────────────

  ═══════════════════════════════════════════════════════════════════
  SCAN SUMMARY
  ═══════════════════════════════════════════════════════════════════
  Target URL           : http://testphp.vulnweb.com
  URLs Scanned         : 5
  Total Tests Run      : 450
  Scan Duration        : 38.21 seconds

  Vulnerabilities Found : 3
    ► Critical    : 1
    ► High        : 2
```

---

## 📝 Report Sample (JSON)

```json
{
  "report_info": {
    "tool": "XSS Finder v1.0",
    "generated_at": "2025-04-19T14:30:00",
    "target_url": "http://testphp.vulnweb.com",
    "scan_duration": "38.21s",
    "urls_scanned": 5,
    "total_tests": 450
  },
  "summary": {
    "total_vulnerabilities": 3,
    "severity_breakdown": {
      "Critical": 1, "High": 2, "Medium": 0, "Low": 0
    }
  },
  "vulnerabilities": [
    {
      "url": "http://testphp.vulnweb.com/search.php",
      "method": "GET",
      "parameter": "searchFor",
      "payload": "<script>alert(1)</script>",
      "vulnerability_type": "Reflected XSS",
      "severity": "High",
      "confidence": "High",
      "poc": "curl -s 'http://testphp.vulnweb.com/search.php?searchFor=...'",
      "remediation": "1. HTML-encode all user-supplied data..."
    }
  ]
}
```

---

## 🔬 Test on Legal Targets

Use these **legally safe** practice targets:

| Target | URL | Notes |
|---|---|---|
| DVWA | http://localhost/dvwa | Local — Docker/XAMPP |
| WebGoat | http://localhost:8080/WebGoat | OWASP project |
| Vulnweb | http://testphp.vulnweb.com | Acunetix practice site |
| HackTheBox | https://hackthebox.com | CTF — requires account |
| TryHackMe | https://tryhackme.com | Beginner friendly |

```bash
# Quick test on legal target:
python main.py --url http://testphp.vulnweb.com --crawl-depth 2 --verbose
```

---

## 🚧 Known Limitations

1. **No JavaScript rendering** — Dynamic content loaded by JS won't be crawled (use `--dom-check` with Selenium for that)
2. **CSRF protection** — Forms with strict CSRF tokens may fail POST injection
3. **Login walls** — Pages behind authentication need `--cookies` with valid session
4. **Rate limiting** — Increase `--delay` if target rate-limits requests

---

## 🔮 Optional Improvements

- [ ] Selenium integration for true DOM XSS detection
- [ ] async/aiohttp for concurrent scanning
- [ ] HTML report with embedded PoC
- [ ] Burp Suite XML import/export
- [ ] Custom payload template engine
- [ ] Slack/webhook notification on critical findings
- [ ] Docker container packaging

---

## ⚠️ Legal Disclaimer

This tool is for **authorized security testing only**. Using XSS Finder against systems without explicit permission is **illegal** under computer fraud laws in most jurisdictions (CFAA, Computer Misuse Act, IT Act, etc.).

The developers assume **no liability** for misuse of this tool.

---

*Built for educational purposes and ethical penetration testing.*
