"""
scanner/injector.py
─────────────────────────────────────────────────────────────────
HTTP Injection Engine
─────────────────────────────────────────────────────────────────
Responsibility:
  - Send GET requests with URL parameters
  - Send POST requests with form data
  - Maintain a persistent HTTP session (reuse connections, cookies)
  - Handle errors gracefully (timeouts, connection refused, etc.)
  - Return raw response objects for downstream analysis
"""

import time
import requests
import urllib3
from urllib.parse import urlencode, urlparse, urlunparse

# Suppress SSL warnings for test environments
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Injector:
    """
    HTTP client responsible for injecting payloads via GET and POST requests.
    Uses a requests.Session for connection reuse and cookie persistence.
    """

    # Common browser-like headers to avoid simple bot detection
    DEFAULT_HEADERS = {
        'Accept'         : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection'     : 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    }

    def __init__(self, timeout, delay, cookies, headers, user_agent, logger):
        """
        Args:
            timeout     (int)  : Request timeout in seconds
            delay       (float): Sleep between requests (rate limiting)
            cookies     (dict) : Cookies to include with every request
            headers     (dict) : Extra HTTP headers
            user_agent  (str)  : User-Agent string
            logger             : Logger instance
        """
        self.timeout    = timeout
        self.delay      = delay
        self.logger     = logger

        # ── Build persistent HTTP session ──────────────────────────────────
        self.session = requests.Session()

        # Set headers: defaults → custom headers → user-agent
        self.session.headers.update(self.DEFAULT_HEADERS)
        self.session.headers.update(headers)
        self.session.headers['User-Agent'] = user_agent

        # Inject cookies
        self.session.cookies.update(cookies)

        # Disable SSL verification (pen-test environments often use self-signed certs)
        self.session.verify = False

        # Track request count for logging
        self._request_count = 0

    # ──────────────────────────────────────────────────────────────────────
    # PUBLIC: GET request
    # ──────────────────────────────────────────────────────────────────────

    def get_request(self, url, params=None):
        """
        Send a GET request to the given URL.
        Optionally append query parameters (used when injecting into URL params).

        Args:
            url    (str) : Target URL
            params (dict): GET query parameters to append to URL

        Returns:
            requests.Response | None: Response object, or None on failure
        """
        self._request_count += 1

        try:
            response = self.session.get(
                url,
                params=params,
                timeout=self.timeout,
                allow_redirects=True
            )
            self.logger.debug(
                f"GET [{response.status_code}] {url[:80]}"
                + (f" params={list(params.keys())}" if params else "")
            )
            return response

        except requests.exceptions.ConnectionError as e:
            self.logger.debug(f"GET ConnectionError: {url[:60]} → {e}")
            return None
        except requests.exceptions.Timeout:
            self.logger.debug(f"GET Timeout: {url[:60]}")
            return None
        except requests.exceptions.TooManyRedirects:
            self.logger.debug(f"GET TooManyRedirects: {url[:60]}")
            return None
        except Exception as e:
            self.logger.debug(f"GET Error [{url[:60]}]: {e}")
            return None

    # ──────────────────────────────────────────────────────────────────────
    # PUBLIC: POST request
    # ──────────────────────────────────────────────────────────────────────

    def post_request(self, url, data):
        """
        Send a POST request with form-encoded data.
        Used for injecting into POST-based form fields.

        Args:
            url  (str) : Target URL (form action)
            data (dict): Form field data to POST

        Returns:
            requests.Response | None: Response object, or None on failure
        """
        self._request_count += 1

        try:
            response = self.session.post(
                url,
                data=data,
                timeout=self.timeout,
                allow_redirects=True
            )
            self.logger.debug(
                f"POST [{response.status_code}] {url[:80]} "
                f"fields={list(data.keys())}"
            )
            return response

        except requests.exceptions.ConnectionError as e:
            self.logger.debug(f"POST ConnectionError: {url[:60]} → {e}")
            return None
        except requests.exceptions.Timeout:
            self.logger.debug(f"POST Timeout: {url[:60]}")
            return None
        except requests.exceptions.TooManyRedirects:
            self.logger.debug(f"POST TooManyRedirects: {url[:60]}")
            return None
        except Exception as e:
            self.logger.debug(f"POST Error [{url[:60]}]: {e}")
            return None

    # ──────────────────────────────────────────────────────────────────────
    # PUBLIC: Utility
    # ──────────────────────────────────────────────────────────────────────

    def build_get_url(self, base_url, params):
        """
        Build a full GET URL by merging base URL with parameters.
        Replaces existing query string completely.

        Args:
            base_url (str) : URL without query string
            params   (dict): Parameters to encode

        Returns:
            str: Complete URL with encoded query string
        """
        if not params:
            return base_url

        parsed = urlparse(base_url)
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            urlencode(params),
            ''  # no fragment
        ))

    @property
    def request_count(self):
        """Return total number of requests made so far."""
        return self._request_count

    def close(self):
        """Close the HTTP session and free resources."""
        self.session.close()
