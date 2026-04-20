"""
scanner/engine.py
─────────────────────────────────────────────────────────────────
Scan Engine — The Central Orchestrator
────────────────────────────────────────────────────────────────
This is the "brain" of XSS Finder. It coordinates all modules:
  1. Crawler      → discovers all URLs and injection points
  2. PayloadMgr   → loads and filters payloads
  3. Injector     → sends HTTP requests with payloads
  4. Detector     → checks responses for XSS indicators
  5. Analyzer     → confirms true positives, reduces false positives
  6. Reporter     → generates final report files
"""

import time
import json
from datetime import datetime
from colorama import Fore, Style

from scanner.crawler import Crawler
from scanner.payload_manager import PayloadManager
from scanner.injector import Injector
from scanner.detector import Detector
from scanner.analyzer import Analyzer
from reports.report_generator import ReportGenerator
from utils.helpers import normalize_url, parse_cookies, parse_headers


class ScanEngine:
    """
    Central orchestrator for the XSS scan.
    Coordinates all modules and manages the scan lifecycle.
    """

    def __init__(self, target_url, crawl_depth, no_crawl, payloads_file,
                 payload_type, output, report_format, threads, timeout,
                 delay, cookies, extra_headers, user_agent, verbose,
                 dom_check, logger):

        # ── Core config ───────────────────────────────────────────────────
        self.target_url   = normalize_url(target_url)
        self.crawl_depth  = crawl_depth
        self.no_crawl     = no_crawl
        self.output       = output
        self.report_format = report_format
        self.threads      = threads
        self.timeout      = timeout
        self.delay        = delay
        self.verbose      = verbose
        self.dom_check    = dom_check
        self.logger       = logger

        # ── Parse cookies and headers ──────────────────────────────────────
        self.cookies      = parse_cookies(cookies) if cookies else {}
        self.custom_headers = parse_headers(extra_headers) if extra_headers else {}
        self.user_agent   = user_agent or (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0 Safari/537.36 XSSFinder/1.0"
        )

        # ── Results tracking ───────────────────────────────────────────────
        self.vulnerabilities = []
        self.scanned_urls    = []
        self.total_tests     = 0
        self.start_time      = None

        # ── Initialize all sub-modules ─────────────────────────────────────
        self.payload_manager = PayloadManager(payloads_file, payload_type, logger)

        self.crawler = Crawler(
            base_url=self.target_url,
            depth=crawl_depth,
            timeout=timeout,
            delay=delay,
            cookies=self.cookies,
            headers=self.custom_headers,
            user_agent=self.user_agent,
            logger=logger
        )

        self.injector = Injector(
            timeout=timeout,
            delay=delay,
            cookies=self.cookies,
            headers=self.custom_headers,
            user_agent=self.user_agent,
            logger=logger
        )

        self.detector = Detector(logger=logger)
        self.analyzer = Analyzer(logger=logger)

    # ──────────────────────────────────────────────────────────────────────
    # PUBLIC: Main run method
    # ──────────────────────────────────────────────────────────────────────

    def run(self):
        """
        Execute the full scan pipeline:
        Phase 1 → Crawl / Info Gathering
        Phase 2 → Payload Preparation
        Phase 3 → Active Injection & Detection
        Phase 4 → Report Generation
        """
        self.start_time = time.time()

        # ─── PHASE 1: Information Gathering ───────────────────────────────
        self.logger.banner("PHASE 1 — INFORMATION GATHERING")

        if self.no_crawl:
            self.logger.info("Crawling disabled. Scanning single target URL only.")
            targets = self._gather_single_url()
        else:
            self.logger.info(f"Starting web crawler (depth={self.crawl_depth})...")
            targets = self.crawler.crawl()

        if not targets:
            self.logger.warning("No injectable targets found. Scan complete.")
            self._print_summary()
            return

        self.logger.success(f"Discovered {len(targets)} injectable target(s) to scan.")

        # ─── PHASE 2: Payload Preparation ─────────────────────────────────
        self.logger.banner("PHASE 2 — PAYLOAD PREPARATION")
        payloads = self.payload_manager.get_payloads()

        if not payloads:
            self.logger.error("No payloads loaded. Cannot proceed with scan.")
            return

        self.logger.success(f"Ready with {len(payloads)} payload(s).")

        # ─── PHASE 3: Active Scanning ──────────────────────────────────────
        self.logger.banner("PHASE 3 — ACTIVE VULNERABILITY SCANNING")
        self._scan_all_targets(targets, payloads)

        # ─── PHASE 4: Report Generation ───────────────────────────────────
        self.logger.banner("PHASE 4 — REPORT GENERATION")
        self._generate_reports()

        # ─── Final Summary ─────────────────────────────────────────────────
        self._print_summary()

    # ──────────────────────────────────────────────────────────────────────
    # PRIVATE: Target gathering
    # ──────────────────────────────────────────────────────────────────────

    def _gather_single_url(self):
        """
        When --no-crawl is used, manually fetch and parse the single URL
        to extract its forms and URL parameters as injection targets.
        """
        import requests
        from bs4 import BeautifulSoup
        import urllib3
        urllib3.disable_warnings()

        targets = []
        try:
            resp = requests.get(
                self.target_url,
                timeout=self.timeout,
                cookies=self.cookies,
                headers={**self.custom_headers, 'User-Agent': self.user_agent},
                verify=False
            )
            soup = BeautifulSoup(resp.text, 'html.parser')

            forms  = self.crawler._extract_forms(soup, self.target_url)
            params = self.crawler._extract_url_params(self.target_url)

            if forms or params:
                targets.append({
                    'url':    self.target_url,
                    'forms':  forms,
                    'params': params
                })
                self.logger.info(
                    f"Single URL | Forms: {len(forms)} | URL Params: {len(params)}"
                )
            else:
                self.logger.warning("No forms or URL parameters found on target page.")

        except Exception as e:
            self.logger.error(f"Failed to fetch target URL: {e}")

        return targets

    # ──────────────────────────────────────────────────────────────────────
    # PRIVATE: Main scanning loop
    # ──────────────────────────────────────────────────────────────────────

    def _scan_all_targets(self, targets, payloads):
        """
        Iterates over every discovered target URL.
        For each target, scans URL params and all form inputs.
        """
        total = len(targets)
        self.logger.info(
            f"Scanning {total} target(s) × {len(payloads)} payload(s) each\n"
        )

        for idx, target in enumerate(targets, 1):
            url    = target['url']
            forms  = target.get('forms', [])
            params = target.get('params', {})

            self.logger.info(
                f"{Fore.CYAN}[{idx}/{total}]{Style.RESET_ALL} → {url}"
            )
            self.scanned_urls.append(url)

            # Test URL parameters (GET-based Reflected XSS)
            if params:
                self.logger.debug(f"       URL Params: {list(params.keys())}")
                self._scan_url_params(url, params, payloads)

            # Test forms (GET/POST-based XSS)
            if forms:
                self.logger.debug(f"       Forms found: {len(forms)}")
                for form_idx, form in enumerate(forms, 1):
                    self.logger.debug(
                        f"       Form [{form_idx}]: method={form.get('method','get').upper()} "
                        f"action={form.get('action', url)}"
                    )
                    self._scan_form(url, form, payloads)

            # Brief delay between target URLs
            time.sleep(self.delay)

    # ──────────────────────────────────────────────────────────────────────
    # PRIVATE: URL Parameter scanning
    # ──────────────────────────────────────────────────────────────────────

    def _scan_url_params(self, url, params, payloads):
        """
        Tests each URL GET parameter by injecting payloads one at a time.
        Other parameters keep their original values during testing.
        """
        from urllib.parse import urlparse, urlencode, urlunparse

        for param_name, original_value in params.items():
            self.logger.debug(f"         Testing param: '{param_name}'")

            for payload in payloads:
                self.total_tests += 1

                try:
                    # Build modified URL with payload injected into this param
                    test_params = dict(params)
                    test_params[param_name] = payload['payload']

                    parsed = urlparse(url)
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, urlencode(test_params), ''
                    ))

                    # Fire the GET request
                    response = self.injector.get_request(test_url)
                    if response is None:
                        continue

                    # Check for XSS indicators
                    detection = self.detector.detect(
                        response=response,
                        payload=payload,
                        context='url_param',
                        param_name=param_name
                    )

                    if detection:
                        # Confirm to avoid false positives
                        if self.analyzer.confirm_vulnerability(response, payload, 'url_param'):
                            vuln = self._build_vulnerability(
                                url=url, method='GET', param=param_name,
                                payload=payload, vuln_type='Reflected XSS',
                                context='URL Parameter', response=response,
                                detection=detection
                            )
                            self.vulnerabilities.append(vuln)
                            self._print_found_vuln(vuln)

                except Exception as e:
                    self.logger.debug(f"         Error on param '{param_name}': {e}")

                time.sleep(self.delay / 2)

    # ──────────────────────────────────────────────────────────────────────
    # PRIVATE: Form scanning
    # ──────────────────────────────────────────────────────────────────────

    def _scan_form(self, page_url, form, payloads):
        """
        Tests each injectable form input field.
        Builds form data with all fields, replacing one field at a time with payload.
        """
        action  = form.get('action', page_url)
        method  = form.get('method', 'get').upper()
        inputs  = form.get('inputs', [])

        # Field types we can inject into
        injectable_types = {'text', 'search', 'email', 'url', 'tel',
                            'password', 'number', 'textarea', 'hidden', ''}

        for field in inputs:
            field_name = field.get('name', '').strip()
            field_type = field.get('type', 'text').lower()

            # Skip non-injectable fields
            if not field_name:
                continue
            if field_type not in injectable_types:
                continue

            self.logger.debug(f"         Testing field: '{field_name}' (type={field_type})")

            for payload in payloads:
                self.total_tests += 1

                try:
                    # Build form data dict — inject into target field only
                    form_data = {}
                    for inp in inputs:
                        iname = inp.get('name', '')
                        if not iname:
                            continue
                        if iname == field_name:
                            form_data[iname] = payload['payload']
                        else:
                            form_data[iname] = inp.get('value', 'test')

                    # Send form via GET or POST
                    if method == 'POST':
                        response = self.injector.post_request(action, form_data)
                    else:
                        response = self.injector.get_request(action, params=form_data)

                    if response is None:
                        continue

                    # Detect XSS
                    detection = self.detector.detect(
                        response=response,
                        payload=payload,
                        context='form_input',
                        param_name=field_name
                    )

                    if detection:
                        if self.analyzer.confirm_vulnerability(response, payload, 'form_input'):
                            # POST forms → potential Stored XSS
                            vuln_type = 'Stored XSS' if method == 'POST' else 'Reflected XSS'
                            vuln = self._build_vulnerability(
                                url=action, method=method, param=field_name,
                                payload=payload, vuln_type=vuln_type,
                                context='Form Input', response=response,
                                detection=detection
                            )
                            self.vulnerabilities.append(vuln)
                            self._print_found_vuln(vuln)

                except Exception as e:
                    self.logger.debug(f"         Error on field '{field_name}': {e}")

                time.sleep(self.delay / 2)

    # ──────────────────────────────────────────────────────────────────────
    # PRIVATE: Vulnerability builder
    # ──────────────────────────────────────────────────────────────────────

    def _build_vulnerability(self, url, method, param, payload,
                              vuln_type, context, response, detection):
        """
        Constructs a structured vulnerability object for reporting.
        """
        severity = self._calc_severity(payload, detection)

        return {
            'timestamp'        : datetime.now().isoformat(),
            'url'              : url,
            'method'           : method,
            'parameter'        : param,
            'payload'          : payload['payload'],
            'payload_type'     : payload.get('type', 'basic'),
            'vulnerability_type': vuln_type,
            'context'          : context,
            'injection_context': detection.get('injection_context', 'html'),
            'severity'         : severity,
            'confidence'       : detection.get('confidence', 'Medium'),
            'response_code'    : response.status_code,
            'evidence'         : detection.get('evidence', ''),
            'poc'              : self._build_poc(url, method, param, payload['payload']),
            'remediation'      : self._get_remediation(vuln_type)
        }

    def _calc_severity(self, payload, detection):
        """
        Calculate severity based on payload type, injection context, and confidence.
        Critical > High > Medium > Low
        """
        ctx        = detection.get('injection_context', 'html')
        confidence = detection.get('confidence', 'Medium')
        ptype      = payload.get('type', 'basic')

        if ctx == 'script' and confidence == 'High':
            return 'Critical'
        if ptype in ('advanced', 'waf_bypass') and confidence == 'High':
            return 'High'
        if confidence == 'High':
            return 'High'
        if confidence == 'Medium':
            return 'Medium'
        return 'Low'

    def _build_poc(self, url, method, param, payload):
        """Create a cURL-based Proof of Concept command."""
        from urllib.parse import quote
        if method == 'GET':
            return f"curl -s '{url}?{param}={quote(payload)}'"
        return f"curl -s -X POST '{url}' --data '{param}={quote(payload)}'"

    def _get_remediation(self, vuln_type):
        """Return remediation advice based on vulnerability type."""
        advice = {
            'Reflected XSS': (
                "1. HTML-encode all user-supplied data before rendering in HTML. "
                "2. Implement a strict Content-Security-Policy (CSP) header. "
                "3. Use framework-level auto-escaping (Django, Jinja2, etc.). "
                "4. Validate and whitelist all user input server-side. "
                "5. Set HttpOnly and Secure flags on session cookies."
            ),
            'Stored XSS': (
                "1. Sanitize all input before storing in the database. "
                "2. Encode output at render time, not just at input time. "
                "3. Use DOMPurify or equivalent on front-end for user HTML. "
                "4. Implement CSP to block inline script execution. "
                "5. Regularly audit database content for stored scripts."
            ),
            'DOM XSS': (
                "1. Replace dangerous sinks (innerHTML, document.write) with safe alternatives. "
                "2. Use textContent instead of innerHTML for untrusted data. "
                "3. Integrate DOMPurify to sanitize HTML before DOM insertion. "
                "4. Avoid eval(), setTimeout(string), Function(string). "
                "5. Enforce a strict CSP with 'script-src self'."
            )
        }
        return advice.get(vuln_type, "Apply strict input validation and output encoding.")

    # ──────────────────────────────────────────────────────────────────────
    # PRIVATE: Console output helpers
    # ──────────────────────────────────────────────────────────────────────

    def _print_found_vuln(self, vuln):
        """Print a concise, colored vulnerability alert to the terminal."""
        sev_color = {
            'Critical': Fore.RED + Style.BRIGHT,
            'High'    : Fore.RED,
            'Medium'  : Fore.YELLOW,
            'Low'     : Fore.CYAN
        }.get(vuln['severity'], Fore.WHITE)

        print()
        print(f"{Fore.GREEN}{'─'*65}{Style.RESET_ALL}")
        print(f"  {Fore.RED}[!!!] VULNERABILITY FOUND{Style.RESET_ALL}")
        print(f"{'─'*65}")
        print(f"  Type        : {sev_color}{vuln['vulnerability_type']}{Style.RESET_ALL}")
        print(f"  Severity    : {sev_color}{vuln['severity']}{Style.RESET_ALL}")
        print(f"  URL         : {vuln['url']}")
        print(f"  Method      : {vuln['method']}")
        print(f"  Parameter   : {Fore.YELLOW}{vuln['parameter']}{Style.RESET_ALL}")
        print(f"  Context     : {vuln['injection_context'].upper()}")
        print(f"  Confidence  : {vuln['confidence']}")
        print(f"  Payload     : {Fore.YELLOW}{vuln['payload']}{Style.RESET_ALL}")
        print(f"  PoC         : {vuln['poc']}")
        print(f"{Fore.GREEN}{'─'*65}{Style.RESET_ALL}")
        print()

    def _print_summary(self):
        """Print final scan summary table."""
        elapsed = time.time() - self.start_time
        total_vulns = len(self.vulnerabilities)

        print(f"\n{Fore.CYAN}{'═'*65}")
        print(f"  SCAN SUMMARY")
        print(f"{'═'*65}{Style.RESET_ALL}")
        print(f"  Target URL           : {self.target_url}")
        print(f"  URLs Scanned         : {len(self.scanned_urls)}")
        print(f"  Total Tests Run      : {self.total_tests}")
        print(f"  Scan Duration        : {elapsed:.2f} seconds")
        print()

        if total_vulns:
            print(f"  {Fore.RED}Vulnerabilities Found : {total_vulns}{Style.RESET_ALL}")
            breakdown = {}
            for v in self.vulnerabilities:
                s = v['severity']
                breakdown[s] = breakdown.get(s, 0) + 1
            order = ['Critical', 'High', 'Medium', 'Low']
            colors = {
                'Critical': Fore.RED + Style.BRIGHT,
                'High': Fore.RED,
                'Medium': Fore.YELLOW,
                'Low': Fore.CYAN
            }
            for sev in order:
                if sev in breakdown:
                    c = colors[sev]
                    print(f"    {c}► {sev:<10}: {breakdown[sev]}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}Vulnerabilities Found : 0 — No XSS detected ✓{Style.RESET_ALL}")

        print(f"{Fore.CYAN}{'═'*65}{Style.RESET_ALL}\n")

    # ──────────────────────────────────────────────────────────────────────
    # PRIVATE: Report generation
    # ──────────────────────────────────────────────────────────────────────

    def _generate_reports(self):
        """Compile all data and call the report generator."""
        elapsed = time.time() - self.start_time

        report_data = {
            'target_url'         : self.target_url,
            'scan_duration'      : f"{elapsed:.2f}s",
            'urls_scanned'       : len(self.scanned_urls),
            'scanned_urls_list'  : self.scanned_urls,
            'total_tests'        : self.total_tests,
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities'    : self.vulnerabilities
        }

        generator = ReportGenerator(
            report_data=report_data,
            output_path=self.output,
            report_format=self.report_format,
            logger=self.logger
        )
        generator.generate()
