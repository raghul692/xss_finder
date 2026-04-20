"""
scanner/crawler.py
─────────────────────────────────────────────────────────────────
Web Crawler Module
─────────────────────────────────────────────────────────────────
Responsibility:
  - Recursively visits all pages on the target site (up to max depth)
  - Extracts every link, form, input field, textarea, and select element
  - Identifies GET parameters from URLs
  - Respects scope (only crawls pages on the same domain)
  - Tracks visited URLs to avoid duplicate work
"""

import requests
import time
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from colorama import Fore, Style
import urllib3

# Suppress SSL certificate warnings (common in pen-test environments)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Crawler:
    """
    Depth-limited web crawler that discovers injectable targets.
    Stays within the same domain as the base URL.
    """

    def __init__(self, base_url, depth, timeout, delay,
                 cookies, headers, user_agent, logger):
        self.base_url      = base_url
        self.max_depth     = depth
        self.timeout       = timeout
        self.delay         = delay
        self.cookies       = cookies
        self.custom_headers = headers
        self.user_agent    = user_agent
        self.logger        = logger

        # ── Domain scope enforcement ───────────────────────────────────────
        parsed = urlparse(base_url)
        self.base_domain = parsed.netloc   # e.g. "testphp.vulnweb.com"
        self.base_scheme = parsed.scheme   # "http" or "https"

        # ── State tracking ─────────────────────────────────────────────────
        self.visited_urls = set()   # URLs already fetched (prevent loops)
        self.targets      = []      # Final list of injectable targets

        # ── Standard session headers ───────────────────────────────────────
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Accept'    : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            **self.custom_headers
        })
        self.session.cookies.update(self.cookies)
        self.session.verify = False   # Allow self-signed certs

    # ──────────────────────────────────────────────────────────────────────
    # PUBLIC: Start crawl
    # ──────────────────────────────────────────────────────────────────────

    def crawl(self):
        """
        Entry point for crawling.
        Starts at base_url and walks all reachable pages up to max_depth.
        Returns a list of target dicts: {url, forms, params}
        """
        self.logger.info(f"Scope       : {self.base_domain}")
        self.logger.info(f"Max Depth   : {self.max_depth}")
        print()

        self._crawl_page(self.base_url, depth=0)

        print()
        self.logger.info(
            f"Crawl complete | Pages visited: {len(self.visited_urls)} | "
            f"Injectable targets: {len(self.targets)}"
        )
        return self.targets

    # ──────────────────────────────────────────────────────────────────────
    # PRIVATE: Recursive page crawler
    # ──────────────────────────────────────────────────────────────────────

    def _crawl_page(self, url, depth):
        """
        Fetch and analyze a single page.
        Recursively follows links found on the page.

        Args:
            url   (str): The URL to fetch
            depth (int): Current crawl depth (0 = starting URL)
        """
        # ── Depth guard ────────────────────────────────────────────────────
        if depth > self.max_depth:
            return

        # ── Duplicate guard ────────────────────────────────────────────────
        # Normalize URL (strip fragment, trailing slash variations)
        clean_url = self._normalize_url_for_dedup(url)
        if clean_url in self.visited_urls:
            return
        self.visited_urls.add(clean_url)

        # ── Protocol guard ─────────────────────────────────────────────────
        if not url.startswith(('http://', 'https://')):
            return

        # ── Domain scope guard ─────────────────────────────────────────────
        if urlparse(url).netloc != self.base_domain:
            return

        indent = '  ' * (depth + 1)
        self.logger.debug(f"{indent}[D{depth}] {url}")

        # ── Fetch page ─────────────────────────────────────────────────────
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except requests.exceptions.ConnectionError:
            self.logger.debug(f"{indent}⚠ Connection refused: {url}")
            return
        except requests.exceptions.Timeout:
            self.logger.debug(f"{indent}⚠ Timeout: {url}")
            return
        except Exception as e:
            self.logger.debug(f"{indent}⚠ Error fetching {url}: {e}")
            return

        # ── Skip non-HTML responses ────────────────────────────────────────
        content_type = response.headers.get('Content-Type', '')
        if 'text/html' not in content_type and 'xhtml' not in content_type:
            self.logger.debug(f"{indent}Skipping non-HTML: {content_type}")
            return

        # ── Parse HTML ─────────────────────────────────────────────────────
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
        except Exception as e:
            self.logger.debug(f"{indent}Parse error: {e}")
            return

        # ── Extract injection points ───────────────────────────────────────
        forms  = self._extract_forms(soup, url)
        params = self._extract_url_params(url)

        if forms or params:
            # This page has something to inject into → add as target
            self.targets.append({
                'url'   : url,
                'forms' : forms,
                'params': params
            })
            marker = f"{Fore.GREEN}[+]{Style.RESET_ALL}"
            self.logger.info(
                f"{marker} {url[:80]}  "
                f"(Forms: {len(forms)}, Params: {len(params)})"
            )
        else:
            self.logger.debug(f"{indent}No injection points at: {url}")

        # ── Follow links if depth allows ───────────────────────────────────
        if depth < self.max_depth:
            links = self._extract_links(soup, url)
            self.logger.debug(f"{indent}Found {len(links)} link(s) to follow")
            for link in links:
                time.sleep(self.delay)
                self._crawl_page(link, depth + 1)

    # ──────────────────────────────────────────────────────────────────────
    # PRIVATE: Extractors
    # ──────────────────────────────────────────────────────────────────────

    def _extract_links(self, soup, current_url):
        """
        Find all <a href="..."> links on the page.
        Converts relative paths to absolute URLs.
        Filters to same-domain links only.
        """
        links = set()

        for tag in soup.find_all('a', href=True):
            href = tag['href'].strip()

            # Skip useless links
            if not href:
                continue
            if href.startswith(('javascript:', 'mailto:', 'tel:', '#', 'data:')):
                continue

            # Convert relative → absolute URL
            absolute = urljoin(current_url, href)

            # Strip fragment (#section)
            parsed = urlparse(absolute)
            absolute = parsed._replace(fragment='').geturl()

            # Keep only same-domain links
            if urlparse(absolute).netloc == self.base_domain:
                links.add(absolute)

        return list(links)

    def _extract_forms(self, soup, current_url):
        """
        Find all <form> elements on the page.
        For each form, extract:
          - action URL (where the form submits to)
          - method (GET or POST)
          - all input, textarea, select fields with their names/types/values

        Returns a list of form dicts.
        """
        forms = []

        for form_tag in soup.find_all('form'):
            # Resolve form action URL
            action = form_tag.get('action', '').strip()
            action = urljoin(current_url, action) if action else current_url

            method = form_tag.get('method', 'get').lower().strip()

            inputs = []

            # ── <input> fields ─────────────────────────────────────────────
            for inp in form_tag.find_all('input'):
                name  = inp.get('name', '').strip()
                itype = inp.get('type', 'text').lower().strip()
                value = inp.get('value', '').strip()

                if name:
                    inputs.append({
                        'tag'  : 'input',
                        'type' : itype,
                        'name' : name,
                        'value': value
                    })

            # ── <textarea> fields ──────────────────────────────────────────
            for textarea in form_tag.find_all('textarea'):
                name = textarea.get('name', '').strip()
                if name:
                    inputs.append({
                        'tag'  : 'textarea',
                        'type' : 'textarea',
                        'name' : name,
                        'value': (textarea.string or '').strip()
                    })

            # ── <select> fields ────────────────────────────────────────────
            for select in form_tag.find_all('select'):
                name = select.get('name', '').strip()
                if name:
                    # Try to grab current selected option value
                    selected = select.find('option', selected=True)
                    value = (selected.get('value', '') if selected else '')
                    inputs.append({
                        'tag'  : 'select',
                        'type' : 'select',
                        'name' : name,
                        'value': value
                    })

            if inputs:
                forms.append({
                    'action': action,
                    'method': method,
                    'inputs': inputs
                })

        return forms

    def _extract_url_params(self, url):
        """
        Parse GET parameters from the URL query string.
        E.g., ?id=1&name=test  →  {'id': '1', 'name': 'test'}
        """
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)

        # parse_qs returns lists: {'id': ['1']} → flatten to {'id': '1'}
        return {k: v[0] for k, v in qs.items()}

    def _normalize_url_for_dedup(self, url):
        """
        Normalize URL for deduplication purposes.
        Strips fragments and sorts query parameters for consistent comparison.
        """
        try:
            parsed = urlparse(url)
            # Sort query params so ?a=1&b=2 == ?b=2&a=1
            from urllib.parse import parse_qs, urlencode
            params = parse_qs(parsed.query)
            sorted_qs = urlencode(sorted(params.items()), doseq=True)
            normalized = parsed._replace(query=sorted_qs, fragment='').geturl()
            return normalized.rstrip('/')
        except Exception:
            return url
