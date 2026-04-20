"""
reports/report_generator.py
─────────────────────────────────────────────────────────────────
Report Generator — Output Formatter
─────────────────────────────────────────────────────────────────
Responsibility:
  - Accept structured vulnerability data from the Scan Engine
  - Sort vulnerabilities by severity (Critical → Low)
  - Generate professional reports in:
      • JSON format (machine-readable, structured)
      • TXT format  (human-readable, detailed)
  - Save reports to disk with timestamps
"""

import json
import os
from datetime import datetime
from colorama import Fore, Style


class ReportGenerator:
    """
    Generates JSON and TXT vulnerability reports from scan results.
    """

    # Severity ranking (lower = more severe)
    SEVERITY_RANK = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}

    # Separator widths
    W_WIDE   = 70
    W_NARROW = 50

    def __init__(self, report_data, output_path, report_format, logger):
        """
        Args:
            report_data   (dict): Full scan results from ScanEngine
            output_path   (str) : Base path for output files (without extension)
            report_format (str) : 'json' | 'txt' | 'both'
            logger               : Logger instance
        """
        self.data          = report_data
        self.output_path   = output_path
        self.report_format = report_format
        self.logger        = logger
        self.timestamp     = datetime.now().strftime('%Y%m%d_%H%M%S')

    # ──────────────────────────────────────────────────────────────────────
    # PUBLIC: Entry point
    # ──────────────────────────────────────────────────────────────────────

    def generate(self):
        """
        Main report generation method.
        Sorts vulnerabilities, then delegates to format-specific generators.
        """
        vulns = self.data.get('vulnerabilities', [])

        if not vulns:
            self.logger.info("No vulnerabilities found — no report generated.")
            return

        # Sort by severity: Critical first, Low last
        self.data['vulnerabilities'] = sorted(
            vulns,
            key=lambda v: self.SEVERITY_RANK.get(v.get('severity', 'Low'), 3)
        )

        # Generate requested format(s)
        if self.report_format in ('json', 'both'):
            path = self._resolve_path('json')
            self._write_json(path)
            self.logger.success(f"JSON report → {path}")

        if self.report_format in ('txt', 'both'):
            path = self._resolve_path('txt')
            self._write_txt(path)
            self.logger.success(f"TXT  report → {path}")

    # ──────────────────────────────────────────────────────────────────────
    # PRIVATE: Path helper
    # ──────────────────────────────────────────────────────────────────────

    def _resolve_path(self, ext):
        """
        Determine the output file path.
        If user provided --output, use that base name.
        Otherwise, auto-generate: xss_report_YYYYMMDD_HHMMSS.ext
        """
        if self.output_path:
            base = os.path.splitext(self.output_path)[0]  # strip extension if any
            return f"{base}.{ext}"
        return f"xss_report_{self.timestamp}.{ext}"

    # ──────────────────────────────────────────────────────────────────────
    # PRIVATE: JSON report
    # ──────────────────────────────────────────────────────────────────────

    def _write_json(self, path):
        """
        Write a machine-readable JSON report.
        Structure:
          report_info → scan metadata
          summary     → counts and breakdowns
          vulnerabilities → full list with all details
        """
        report = {
            'report_info': {
                'tool'        : 'XSS Finder v1.0',
                'generated_at': datetime.now().isoformat(),
                'target_url'  : self.data.get('target_url', ''),
                'scan_duration': self.data.get('scan_duration', ''),
                'urls_scanned': self.data.get('urls_scanned', 0),
                'total_tests' : self.data.get('total_tests', 0),
            },
            'summary': {
                'total_vulnerabilities': len(self.data.get('vulnerabilities', [])),
                'severity_breakdown'   : self._severity_breakdown(),
                'type_breakdown'       : self._type_breakdown(),
                'scanned_urls'         : self.data.get('scanned_urls_list', [])
            },
            'vulnerabilities': self.data.get('vulnerabilities', [])
        }

        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

    # ──────────────────────────────────────────────────────────────────────
    # PRIVATE: TXT report
    # ──────────────────────────────────────────────────────────────────────

    def _write_txt(self, path):
        """
        Write a human-readable plain text report.
        Includes full vulnerability details with PoC and remediation.
        """
        lines = []
        vulns = self.data.get('vulnerabilities', [])
        W     = self.W_WIDE

        # ── Header ────────────────────────────────────────────────────────
        lines += [
            '=' * W,
            '              XSS FINDER — VULNERABILITY REPORT              ',
            '=' * W,
            f"Generated At   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Tool           : XSS Finder v1.0",
            f"Target URL     : {self.data.get('target_url', 'N/A')}",
            f"Scan Duration  : {self.data.get('scan_duration', 'N/A')}",
            f"URLs Scanned   : {self.data.get('urls_scanned', 0)}",
            f"Total Tests    : {self.data.get('total_tests', 0)}",
            f"Vulnerabilities: {len(vulns)}",
            '',
        ]

        # ── Severity Summary ──────────────────────────────────────────────
        lines += [
            '-' * W,
            'SEVERITY SUMMARY',
            '-' * W,
        ]
        breakdown = self._severity_breakdown()
        for sev in ['Critical', 'High', 'Medium', 'Low']:
            count = breakdown.get(sev, 0)
            marker = '<!>' if count > 0 else '   '
            lines.append(f"  {marker}  {sev:<12}: {count}")
        lines.append('')

        # ── Type Summary ──────────────────────────────────────────────────
        lines += [
            '-' * W,
            'VULNERABILITY TYPE BREAKDOWN',
            '-' * W,
        ]
        type_bd = self._type_breakdown()
        for vtype, count in type_bd.items():
            lines.append(f"     {vtype:<30}: {count}")
        lines.append('')

        # ── Vulnerability Details ─────────────────────────────────────────
        lines += [
            '=' * W,
            'DETAILED VULNERABILITY FINDINGS',
            '=' * W,
        ]

        for idx, vuln in enumerate(vulns, 1):
            sev    = vuln.get('severity', 'N/A')
            vtype  = vuln.get('vulnerability_type', 'XSS')
            marker = '!!!' if sev in ('Critical', 'High') else '  !'

            lines += [
                '',
                f"[{idx}] [{marker}] {vtype} — Severity: {sev}",
                '-' * self.W_NARROW,
                f"  Timestamp      : {vuln.get('timestamp', 'N/A')}",
                f"  URL            : {vuln.get('url', 'N/A')}",
                f"  HTTP Method    : {vuln.get('method', 'N/A')}",
                f"  Parameter      : {vuln.get('parameter', 'N/A')}",
                f"  Inj. Context   : {vuln.get('injection_context', 'N/A')}",
                f"  Input Context  : {vuln.get('context', 'N/A')}",
                f"  Payload Type   : {vuln.get('payload_type', 'N/A')}",
                f"  Severity       : {sev}",
                f"  Confidence     : {vuln.get('confidence', 'N/A')}",
                f"  HTTP Status    : {vuln.get('response_code', 'N/A')}",
                '',
                f"  PAYLOAD:",
                f"    {vuln.get('payload', 'N/A')}",
                '',
                f"  EVIDENCE (response snippet):",
                f"    {vuln.get('evidence', 'N/A')[:250]}",
                '',
                f"  PROOF OF CONCEPT (PoC):",
                f"    {vuln.get('poc', 'N/A')}",
                '',
                f"  REMEDIATION:",
            ]

            # Word-wrap remediation text
            remediation = vuln.get('remediation', '')
            for step in remediation.split('. '):
                step = step.strip()
                if step:
                    lines.append(f"    • {step}.")
            lines.append('')

        # ── Footer ────────────────────────────────────────────────────────
        lines += [
            '=' * W,
            f"  END OF REPORT — Generated by XSS Finder v1.0",
            f"  IMPORTANT: This report is for authorized testing only.",
            f"  Do not use findings for malicious purposes.",
            '=' * W,
        ]

        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))

    # ──────────────────────────────────────────────────────────────────────
    # PRIVATE: Breakdown helpers
    # ──────────────────────────────────────────────────────────────────────

    def _severity_breakdown(self):
        """Count vulnerabilities per severity level."""
        counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for v in self.data.get('vulnerabilities', []):
            sev = v.get('severity', 'Low')
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _type_breakdown(self):
        """Count vulnerabilities per vulnerability type."""
        counts = {}
        for v in self.data.get('vulnerabilities', []):
            vt = v.get('vulnerability_type', 'Unknown')
            counts[vt] = counts.get(vt, 0) + 1
        return counts
