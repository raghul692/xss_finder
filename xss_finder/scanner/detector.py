"""
scanner/detector.py
─────────────────────────────────────────────────────────────────
XSS Detection Engine
─────────────────────────────────────────────────────────────────
Responsibility:
  - Inspect HTTP responses for signs of XSS vulnerability
  - Use multiple detection techniques:
      1. Raw payload reflection check
      2. HTML entity encoding check (encoded = NOT vulnerable)
      3. Injection context identification (HTML/script/attribute)
      4. Execution pattern matching (confidence scoring)
  - Return a structured detection result dict or None
"""

import re
from bs4 import BeautifulSoup


class Detector:
    """
    Multi-technique XSS detector.
    Analyses HTTP responses to determine if a payload was reflected
    in an executable context (indicating XSS vulnerability).
    """

    # ── HTML entity encodings for dangerous characters ─────────────────────
    # If these appear instead of raw chars → server encoded → NOT vulnerable
    HTML_ENTITY_MAP = {
        '<' : ['&lt;', '&#60;', '&#x3c;', '&#x3C;', '%3C', '%3c'],
        '>' : ['&gt;', '&#62;', '&#x3e;', '&#x3E;', '%3E', '%3e'],
        '"' : ['&quot;', '&#34;', '&#x22;', '%22'],
        "'" : ['&#39;', '&#x27;', '&apos;', '%27'],
        '(' : ['&#40;', '&#x28;', '%28'],
        ')' : ['&#41;', '&#x29;', '%29'],
        '/' : ['&#47;', '&#x2f;', '%2f', '%2F'],
    }

    # ── Patterns indicating script execution capability ────────────────────
    EXECUTION_PATTERNS = [
        r'<script[\s>][^<]*?alert\s*\(',
        r'<script[\s>][^<]*?confirm\s*\(',
        r'<script[\s>][^<]*?prompt\s*\(',
        r'<script[^>]*>[^<]*</script>',
        r'on(?:load|click|focus|mouseover|error|submit|keyup|keydown)\s*=\s*["\']?[^"\'>]+',
        r'javascript\s*:',
        r'<img[^>]+onerror\s*=',
        r'<svg[^>]+onload\s*=',
        r'<body[^>]+onload\s*=',
        r'<iframe[^>]+src\s*=\s*["\']?javascript:',
        r'<input[^>]+onfocus\s*=',
        r'<details[^>]+ontoggle\s*=',
    ]

    def __init__(self, logger):
        self.logger = logger

        # Pre-compile regex patterns for performance
        self._exec_patterns = [
            re.compile(pat, re.IGNORECASE | re.DOTALL)
            for pat in self.EXECUTION_PATTERNS
        ]

    # ──────────────────────────────────────────────────────────────────────
    # PUBLIC: Main detect method
    # ──────────────────────────────────────────────────────────────────────

    def detect(self, response, payload, context, param_name):
        """
        Run all detection techniques against the HTTP response.

        Args:
            response   : requests.Response object
            payload    (dict): {'payload': str, 'type': str}
            context    (str) : 'url_param' or 'form_input'
            param_name (str) : Name of the tested parameter

        Returns:
            dict | None: Detection result, or None if no XSS detected
        """
        if response is None:
            return None

        body         = response.text
        payload_str  = payload['payload']

        # ── Step 1: Check raw reflection ───────────────────────────────────
        if not self._is_reflected(body, payload_str):
            # Payload not in response at all → no XSS
            return None

        # ── Step 2: Check if payload was HTML-encoded ──────────────────────
        if self._is_encoded(body, payload_str):
            # Payload was escaped → NOT vulnerable
            self.logger.debug(f"           Reflected but encoded (safe): {payload_str[:40]}")
            return None

        # ── Step 3: Identify injection context (where in HTML is it?) ──────
        injection_ctx = self._identify_context(body, payload_str)

        # ── Step 4: Calculate confidence score ────────────────────────────
        confidence = self._calculate_confidence(body, payload_str, injection_ctx)

        # ── Step 5: Extract evidence snippet ──────────────────────────────
        evidence = self._extract_evidence(body, payload_str)

        self.logger.debug(
            f"           ✓ DETECTED | ctx={injection_ctx} | "
            f"confidence={confidence} | param={param_name}"
        )

        return {
            'reflected'        : True,
            'encoded'          : False,
            'injection_context': injection_ctx,
            'confidence'       : confidence,
            'evidence'         : evidence
        }

    # ──────────────────────────────────────────────────────────────────────
    # PRIVATE: Detection techniques
    # ──────────────────────────────────────────────────────────────────────

    def _is_reflected(self, body, payload):
        """
        Technique 1: Check if the exact payload string exists anywhere in the response.
        This is the first (fastest) check.
        """
        return payload in body

    def _is_encoded(self, body, payload):
        """
        Technique 2: Determine if dangerous characters were HTML-encoded.

        Logic:
          - For each dangerous char in the payload
          - Check if the body contains the encoded version of the entire payload
            (i.e., the payload with that char replaced by its entity)
          - If yes AND the raw payload is NOT present → encoded (safe)
          - Special: if both encoded AND raw are present, still vulnerable
        """
        dangerous = [c for c in ['<', '>', '"', "'", '(', ')'] if c in payload]

        if not dangerous:
            # Payload has no dangerous chars → can't determine encoding
            return False

        # Check if ANY of the dangerous chars appear encoded
        for char in dangerous:
            for entity in self.HTML_ENTITY_MAP.get(char, []):
                # Try building an encoded variant of the payload
                encoded_variant = payload.replace(char, entity)
                if encoded_variant in body and payload not in body:
                    return True

        return False

    def _identify_context(self, body, payload):
        """
        Technique 3: Determine where in the HTML the payload is injected.
        This affects severity and exploitability.

        Returns one of:
            'script'     → inside a <script> block (most dangerous)
            'attribute'  → inside an HTML tag attribute
            'html'       → in regular HTML body (default)
            'comment'    → inside HTML comment (<!-- -->)
            'unknown'    → could not determine
        """
        try:
            soup = BeautifulSoup(body, 'html.parser')

            # Check if payload is inside a <script> tag body
            for script_tag in soup.find_all('script'):
                if script_tag.string and payload in script_tag.string:
                    return 'script'

            # Check if payload is inside an HTML attribute value
            for tag in soup.find_all(True):
                for attr_name, attr_val in tag.attrs.items():
                    if isinstance(attr_val, str) and payload in attr_val:
                        return 'attribute'
                    elif isinstance(attr_val, list):
                        if any(payload in v for v in attr_val if isinstance(v, str)):
                            return 'attribute'

            # Check if payload is inside an HTML comment
            from bs4 import Comment
            for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
                if payload in str(comment):
                    return 'comment'

        except Exception:
            pass

        # Default: it's in the HTML body somewhere
        return 'html'

    def _calculate_confidence(self, body, payload, injection_ctx):
        """
        Technique 4: Score confidence based on:
          - Injection context
          - Presence of executable patterns (script tags, event handlers, etc.)
          - Payload type indicators

        Returns: 'High' | 'Medium' | 'Low'
        """
        # Inside a <script> block → High confidence
        if injection_ctx == 'script':
            return 'High'

        # Check execution-related patterns in body near payload
        for pattern in self._exec_patterns:
            match = pattern.search(body)
            if match:
                # Confirm the payload is in the same region
                match_pos   = match.start()
                payload_pos = body.find(payload)
                if abs(match_pos - payload_pos) < 500:
                    return 'High'

        # Script tags present in payload itself
        if '<script' in payload.lower() and payload in body:
            return 'High'

        # Event handler in payload
        if re.search(r'\bon\w+\s*=', payload, re.IGNORECASE) and payload in body:
            return 'High'

        # javascript: protocol
        if 'javascript:' in payload.lower() and payload in body:
            return 'Medium'

        # Just reflected, no clear execution vector
        return 'Medium'

    def _extract_evidence(self, body, payload):
        """
        Extract a short snippet of the response around the reflected payload.
        This acts as "proof" for the vulnerability report.

        Returns:
            str: Surrounding HTML context (up to 300 chars)
        """
        try:
            idx = body.find(payload)
            if idx == -1:
                return ''

            # 120 chars before and after the payload
            start = max(0, idx - 120)
            end   = min(len(body), idx + len(payload) + 120)

            snippet = body[start:end]
            # Collapse whitespace for readability
            snippet = ' '.join(snippet.split())
            return snippet[:300]

        except Exception:
            return ''
