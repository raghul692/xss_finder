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

    W_WIDE   = 70
    W_NARROW = 50

    def __init__(self, report_data, output_path, report_format, logger):
        self.data          = report_data
        self.output_path   = output_path
        self.report_format = report_format
        self.logger        = logger
        self.timestamp     = datetime.now().strftime('%Y%m%d_%H%M%S')

    def generate(self):
        """Sort vulnerabilities, then write report files."""
        vulns = self.data.get('vulnerabilities', [])

        if not vulns:
            self.logger.info("No vulnerabilities found — no report generated.")
            return

        self.data['vulnerabilities'] = sorted(
            vulns,
            key=lambda v: self.SEVERITY_RANK.get(v.get('severity', 'Low'), 3)
        )

        if self.report_format in ('json', 'both'):
            path = self._resolve_path('json')
            self._write_json(path)
            self.logger.success(f"JSON report → {path}")

        if self.report_format in ('txt', 'both'):
            path = self._resolve_path('txt')
            self._write_txt(path)
            self.logger.success(f"TXT  report → {path}")

    def _resolve_path(self, ext):
        if self.output_path:
            base = os.path.splitext(self.output_path)[0]
            return f"{base}.{ext}"
        return f"xss_report_{self.timestamp}.{ext}"

    def _write_json(self, path):
        report = {
            'report_info': {
                'tool'         : 'XSS Finder v1.0',
                'generated_at' : datetime.now().isoformat(),
                'target_url'   : self.data.get('target_url', ''),
                'scan_duration': self.data.get('scan_duration', ''),
                'urls_scanned' : self.data.get('urls_scanned', 0),
                'total_tests'  : self.data.get('total_tests', 0),
            },
            'summary': {
                'total_vulnerabilities': len(self.data.get('vulnerabilities', [])),
                'severity_breakdown'   : self._severity_breakdown(),
                'type_breakdown'       : self._type_breakdown(),
                'scanned_urls'         : self.data.get('scanned_urls_list', [])
            },
            'vulnerabilities': self.data.get('vulnerabilities', [])
        }
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

    def _write_txt(self, path):
        lines = []
        vulns = self.data.get('vulnerabilities', [])
        W     = self.W_WIDE

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
            '-' * W,
            'SEVERITY SUMMARY',
            '-' * W,
        ]

        breakdown = self._severity_breakdown()
        for sev in ['Critical', 'High', 'Medium', 'Low']:
            count  = breakdown.get(sev, 0)
            marker = '<!>' if count > 0 else '   '
            lines.append(f"  {marker}  {sev:<12}: {count}")
        lines.append('')

        lines += [
            '-' * W,
            'VULNERABILITY TYPE BREAKDOWN',
            '-' * W,
        ]
        for vtype, count in self._type_breakdown().items():
            lines.append(f"     {vtype:<30}: {count}")
        lines.append('')

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
            for step in vuln.get('remediation', '').split('. '):
                step = step.strip()
                if step:
                    lines.append(f"    • {step}.")
            lines.append('')

        lines += [
            '=' * W,
            f"  END OF REPORT — Generated by XSS Finder v1.0",
            f"  IMPORTANT: For authorized security testing only.",
            '=' * W,
        ]

        with open(path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))

    def _severity_breakdown(self):
        counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for v in self.data.get('vulnerabilities', []):
            sev = v.get('severity', 'Low')
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _type_breakdown(self):
        counts = {}
        for v in self.data.get('vulnerabilities', []):
            vt = v.get('vulnerability_type', 'Unknown')
            counts[vt] = counts.get(vt, 0) + 1
        return counts
