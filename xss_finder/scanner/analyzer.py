"""
scanner/analyzer.py
─────────────────────────────────────────────────────────────────
Response Analyzer — False Positive Reducer
─────────────────────────────────────────────────────────────────
Responsibility:
  - Provide a second opinion after Detector flags a potential XSS
  - Run multi-stage validation to filter out false positives
  - Check:
      • Response content type is actually HTML
      • Payload structure is preserved (not partially matched)
      • WAF is not intercepting the request
      • The injected content appears in a meaningful (executable) location
  - Return True (confirmed) or False (false positive, skip)
"""

import re
from bs4 import BeautifulSoup


class Analyzer:
    """
    Second-stage validator that confirms XSS detections and
    reduces false positives before adding to the vulnerability list.
    """

    # WAF signatures — common strings in WAF-blocked responses
    WAF_SIGNATURES = [
        'access denied',
        'request blocked',
        'forbidden by policy',
        'security violation',
        'illegal request',
        'attack detected',
        'mod_security',
        'cloudflare ray id',
        'sucuri website firewall',
        'bad request',
        'not acceptable',
        'request rejected',
        'this page cannot be displayed',
    ]

    # HTTP status codes that usually mean WAF/rate-limiting
    WAF_STATUS_CODES = {403, 406, 429, 503, 400}

    def __init__(self, logger):
        self.logger = logger

    # ──────────────────────────────────────────────────────────────────────
    # PUBLIC: Main confirmation method
    # ──────────────────────────────────────────────────────────────────────

    def confirm_vulnerability(self, response, payload, context):
        """
        Multi-stage confirmation pipeline.
        Runs 5 checks — ALL must pass for the vulnerability to be confirmed.

        Args:
            response : requests.Response object
            payload  (dict): {'payload': str, 'type': str}
            context  (str) : 'url_param' | 'form_input'

        Returns:
            bool: True if confirmed vulnerable, False if likely false positive
        """
        body        = response.text
        payload_str = payload['payload']

        # ── Check 1: Payload still present in response ─────────────────────
        if payload_str not in body:
            self.logger.debug("    [Confirm FAIL] Payload not found in response body")
            return False

        # ── Check 2: Response is HTML ──────────────────────────────────────
        if not self._is_html_response(response):
            self.logger.debug("    [Confirm FAIL] Response is not HTML")
            return False

        # ── Check 3: WAF is not blocking ───────────────────────────────────
        if self._is_waf_blocked(response, payload_str):
            self.logger.debug("    [Confirm FAIL] WAF blocking detected")
            return False

        # ── Check 4: Payload structure is intact ───────────────────────────
        if not self._is_structure_intact(body, payload_str):
            self.logger.debug("    [Confirm FAIL] Payload structure broken/partial")
            return False

        # ── Check 5: Payload is in an executable location ──────────────────
        executable = self._is_in_executable_context(body, payload_str)
        if not executable:
            self.logger.debug(
                "    [Confirm PASS-LOW] Payload reflected but not in executable context"
            )
            # Still return True — reflection is a finding even without confirmed execution
            return True

        self.logger.debug("    [Confirm PASS-HIGH] Vulnerability confirmed")
        return True

    # ──────────────────────────────────────────────────────────────────────
    # PRIVATE: Individual checks
    # ──────────────────────────────────────────────────────────────────────

    def _is_html_response(self, response):
        """
        Verify the response Content-Type is HTML.
        XSS only applies in HTML contexts (not JSON, plain text, images, etc.)
        """
        ct = response.headers.get('Content-Type', '').lower()
        return 'text/html' in ct or 'application/xhtml' in ct

    def _is_waf_blocked(self, response, payload):
        """
        Detect if a WAF intercepted and blocked the request.
        Signs: status code 403/406/429/503 OR WAF signature in response body.
        """
        # Status code check
        if response.status_code in self.WAF_STATUS_CODES:
            return True

        # Body signature check (only if payload is NOT in body — WAF replaced it)
        body_lower = response.text.lower()
        for sig in self.WAF_SIGNATURES:
            if sig in body_lower and payload not in response.text:
                return True

        return False

    def _is_structure_intact(self, body, payload):
        """
        Verify the key dangerous characters in the payload appear raw (not encoded).
        If '<' and '>' are present in the payload, they must appear as literal
        characters in the response — not as &lt; &gt;.

        Partial encoding (some chars encoded, some not) → structure broken.
        """
        # If payload doesn't contain angle brackets, no structure to verify
        if '<' not in payload and '>' not in payload:
            return payload in body

        # Payload has angle brackets — check they're NOT entity-encoded
        if '&lt;' in body or '&#60;' in body:
            # Some encoding present. Check if the raw payload is ALSO there.
            return payload in body

        return payload in body

    def _is_in_executable_context(self, body, payload):
        """
        Check whether the reflected payload appears in a location
        where it could actually execute JavaScript.

        Executable locations:
          - Inside a <script> block
          - In an event handler attribute (onclick, onerror, etc.)
          - As a javascript: URI
          - As a raw <script> tag in the body
        """
        try:
            soup = BeautifulSoup(body, 'html.parser')

            # Check <script> blocks
            for script in soup.find_all('script'):
                if script.string and payload in script.string:
                    return True

            # Check event handler attributes on any tag
            event_attrs = {
                'onclick', 'ondblclick', 'onmouseover', 'onmouseout',
                'onload', 'onerror', 'onkeyup', 'onkeydown', 'onkeypress',
                'onsubmit', 'onfocus', 'onblur', 'onchange', 'oninput',
                'ontoggle', 'oncontextmenu', 'onscroll'
            }
            for tag in soup.find_all(True):
                for attr in event_attrs:
                    val = tag.get(attr, '')
                    if val and payload in val:
                        return True

            # Check href / src for javascript: protocol
            for tag in soup.find_all(['a', 'iframe', 'form', 'object', 'embed']):
                for attr in ['href', 'src', 'action', 'data']:
                    val = tag.get(attr, '')
                    if 'javascript:' in val.lower() and payload in val:
                        return True

        except Exception:
            pass

        # Check with regex as fallback
        exec_patterns = [
            r'<script[^>]*>.*?' + re.escape(payload[:20]),
            r'on\w+\s*=\s*["\']?' + re.escape(payload[:15]),
        ]
        for pat in exec_patterns:
            try:
                if re.search(pat, body, re.IGNORECASE | re.DOTALL):
                    return True
            except re.error:
                pass

        # Payload reflected but not in executable context
        return False

    # ──────────────────────────────────────────────────────────────────────
    # PUBLIC: Deep context analysis (used in reporting)
    # ──────────────────────────────────────────────────────────────────────

    def deep_context_analysis(self, body, payload):
        """
        Provides detailed context information about where the payload appears.
        Used to generate richer evidence in vulnerability reports.

        Returns:
            dict with keys:
                raw_reflection, in_script, in_attribute, in_comment,
                attr_name, tag_name, near_execution_pattern
        """
        result = {
            'raw_reflection'       : payload in body,
            'in_script'            : False,
            'in_attribute'         : False,
            'in_comment'           : False,
            'attr_name'            : None,
            'tag_name'             : None,
            'near_execution_pattern': False,
        }

        if not result['raw_reflection']:
            return result

        try:
            soup = BeautifulSoup(body, 'html.parser')

            # Script check
            for script in soup.find_all('script'):
                if script.string and payload in script.string:
                    result['in_script'] = True

            # Attribute check
            for tag in soup.find_all(True):
                for attr, val in tag.attrs.items():
                    if isinstance(val, str) and payload in val:
                        result['in_attribute'] = True
                        result['attr_name']    = attr
                        result['tag_name']     = tag.name
                        break

            # Comment check
            from bs4 import Comment
            for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
                if payload in str(comment):
                    result['in_comment'] = True

        except Exception:
            pass

        # Execution pattern check
        for pat in [r'<script', r'on\w+=', r'javascript:']:
            if re.search(pat, body[max(0, body.find(payload)-200):body.find(payload)+200],
                         re.IGNORECASE):
                result['near_execution_pattern'] = True
                break

        return result
