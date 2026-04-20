"""
scanner/payload_manager.py
─────────────────────────────────────────────────────────────────
Payload Manager Module
─────────────────────────────────────────────────────────────────
Responsibility:
  - Load XSS payloads from a text file
  - Categorize payloads into: basic, advanced, waf_bypass, dom
  - Filter payloads by category based on user choice
  - Provide context-aware payload selection (attribute, script, html)

Payload file format:
  # Comment lines start with #
  [BASIC]           ← category marker
  <script>alert(1)</script>
  [ADVANCED]
  ...payload...
"""

import os
from colorama import Fore, Style


class PayloadManager:
    """
    Loads and manages XSS payloads from a file.
    Supports category-based filtering and context-aware selection.
    """

    # Valid category markers in the payload file
    CATEGORY_MARKERS = {
        '[BASIC]'      : 'basic',
        '[ADVANCED]'   : 'advanced',
        '[WAF_BYPASS]' : 'waf_bypass',
        '[DOM]'        : 'dom',
    }

    # Friendly display names for logging
    CATEGORY_LABELS = {
        'basic'      : 'Basic XSS',
        'advanced'   : 'Advanced XSS',
        'waf_bypass' : 'WAF Bypass',
        'dom'        : 'DOM-based XSS',
    }

    def __init__(self, payloads_file, payload_type, logger):
        """
        Args:
            payloads_file (str): Path to the payloads .txt file
            payload_type  (str): 'basic' | 'advanced' | 'waf_bypass' | 'dom' | 'all'
            logger        : Logger instance
        """
        self.payloads_file = payloads_file
        self.payload_type  = payload_type
        self.logger        = logger

        # Will hold all loaded payloads as dicts
        self.all_payloads = []

        # Load from file
        self._load()

    # ──────────────────────────────────────────────────────────────────────
    # PUBLIC
    # ──────────────────────────────────────────────────────────────────────

    def get_payloads(self):
        """
        Return filtered list of payloads based on selected payload_type.
        Falls back to all payloads if the selected type has none.

        Returns:
            list[dict]: Each dict has 'payload' (str) and 'type' (str)
        """
        if self.payload_type == 'all':
            selected = self.all_payloads
        else:
            selected = [
                p for p in self.all_payloads
                if p['type'] == self.payload_type
            ]

        if not selected:
            self.logger.warning(
                f"No payloads found for type '{self.payload_type}'. "
                f"Falling back to all payloads."
            )
            selected = self.all_payloads

        label = self.CATEGORY_LABELS.get(self.payload_type, self.payload_type)
        self.logger.info(
            f"Selected {len(selected)} payload(s) "
            f"[type: {label if self.payload_type != 'all' else 'All Categories'}]"
        )
        return selected

    def get_context_payloads(self, context):
        """
        Return payloads best suited for a specific injection context.

        Contexts:
            'html'      → default HTML body injection
            'attribute' → inside an HTML attribute value
            'script'    → inside a <script> block
            'dom'       → DOM-based injection points
            'url'       → injected into URL/href

        Args:
            context (str): Injection context identifier

        Returns:
            list[dict]: Filtered payloads for the context
        """
        if context == 'dom':
            return [p for p in self.all_payloads if p['type'] in ('dom', 'advanced')]

        elif context == 'attribute':
            # Attribute context needs quote-breaking payloads
            return [
                p for p in self.all_payloads
                if '"' in p['payload'] or "'" in p['payload']
                or p['type'] in ('advanced', 'waf_bypass')
            ]

        elif context == 'script':
            # JS string-breaking payloads
            return [
                p for p in self.all_payloads
                if p['type'] in ('advanced', 'waf_bypass')
                or '</script>' in p['payload']
            ]

        elif context == 'url':
            return [
                p for p in self.all_payloads
                if 'javascript:' in p['payload'].lower()
                or p['type'] in ('advanced',)
            ]

        # Default: return everything
        return self.all_payloads

    def get_stats(self):
        """Return payload count per category as a dict."""
        stats = {}
        for p in self.all_payloads:
            cat = p['type']
            stats[cat] = stats.get(cat, 0) + 1
        return stats

    # ──────────────────────────────────────────────────────────────────────
    # PRIVATE
    # ──────────────────────────────────────────────────────────────────────

    def _load(self):
        """
        Read and parse the payloads file.
        Lines starting with # are comments.
        Lines matching a CATEGORY_MARKER change the active category.
        All other non-empty lines are treated as payloads.
        """
        if not os.path.exists(self.payloads_file):
            self.logger.error(f"Payload file not found: '{self.payloads_file}'")
            return

        current_category = 'basic'   # Default category for payloads before first marker
        loaded_count     = 0
        skipped_count    = 0

        self.logger.debug(f"Loading payloads from: {self.payloads_file}")

        with open(self.payloads_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, raw_line in enumerate(f, start=1):
                line = raw_line.strip()

                # Skip blank lines
                if not line:
                    continue

                # Skip comment lines
                if line.startswith('#'):
                    continue

                # Check for category marker (case-insensitive)
                upper_line = line.upper()
                if upper_line in self.CATEGORY_MARKERS:
                    current_category = self.CATEGORY_MARKERS[upper_line]
                    self.logger.debug(
                        f"  Line {line_num}: Category switched to [{current_category}]"
                    )
                    continue

                # Validate payload is not empty after stripping
                if len(line) < 3:
                    skipped_count += 1
                    continue

                # Add to payloads list
                self.all_payloads.append({
                    'payload': line,
                    'type'   : current_category
                })
                loaded_count += 1

        # ── Print summary ──────────────────────────────────────────────────
        self.logger.info(
            f"Payloads loaded: {loaded_count} total "
            f"({skipped_count} skipped)"
        )

        stats = self.get_stats()
        for cat, count in stats.items():
            label = self.CATEGORY_LABELS.get(cat, cat)
            self.logger.debug(f"   [{label}]: {count} payload(s)")

        if loaded_count == 0:
            self.logger.warning(
                "Payload file is empty or contains only comments! "
                "Please add XSS payloads to the file."
            )
