"""
utils/logger.py
─────────────────────────────────────────────────────────────────
Colored Terminal Logger
─────────────────────────────────────────────────────────────────
Provides consistent, colored console output throughout the tool.

Color scheme:
  [*] INFO    → Cyan
  [+] SUCCESS → Green
  [!] WARNING → Yellow
  [✗] ERROR   → Red (bright)
  [~] DEBUG   → Magenta (only shown with --verbose)
"""

from colorama import Fore, Back, Style
from datetime import datetime


class Logger:
    """
    Simple colored console logger.
    Debug messages are only shown when verbose=True.
    """

    def __init__(self, verbose=False):
        self.verbose = verbose

    # ──────────────────────────────────────────────────────────────────────
    # Log levels
    # ──────────────────────────────────────────────────────────────────────

    def info(self, message):
        """General information message (cyan)."""
        print(f"  {Fore.CYAN}[*]{Style.RESET_ALL} {message}")

    def success(self, message):
        """Success / finding confirmed (green)."""
        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {message}")

    def warning(self, message):
        """Warning / non-critical issue (yellow)."""
        print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} {message}")

    def error(self, message):
        """Error / critical failure (red + bright)."""
        print(f"  {Fore.RED + Style.BRIGHT}[✗]{Style.RESET_ALL} {message}")

    def debug(self, message):
        """Debug detail — only printed when verbose=True (magenta)."""
        if self.verbose:
            print(f"  {Fore.MAGENTA}[~]{Style.RESET_ALL} {message}")

    def banner(self, title):
        """Section header / phase banner."""
        width = 65
        print()
        print(f"  {Fore.BLUE + Style.BRIGHT}{'─' * width}{Style.RESET_ALL}")
        print(f"  {Fore.BLUE + Style.BRIGHT}  {title}{Style.RESET_ALL}")
        print(f"  {Fore.BLUE + Style.BRIGHT}{'─' * width}{Style.RESET_ALL}")

    def section(self, title):
        """Smaller section divider."""
        print(f"  {Fore.CYAN}── {title} {'─' * (55 - len(title))}{Style.RESET_ALL}")

    def plain(self, message):
        """Plain text with no prefix or color."""
        print(f"  {message}")

    def vuln_alert(self, vuln_type, severity, url, param):
        """
        One-line vulnerability alert (compact version for verbose scan output).
        Used during scanning to show progress without full details.
        """
        sev_color = {
            'Critical': Fore.RED + Style.BRIGHT,
            'High'    : Fore.RED,
            'Medium'  : Fore.YELLOW,
            'Low'     : Fore.CYAN
        }.get(severity, Fore.WHITE)

        print(
            f"  {Fore.RED}[VULN]{Style.RESET_ALL} "
            f"{sev_color}{severity:<8}{Style.RESET_ALL} | "
            f"{vuln_type:<15} | "
            f"param={Fore.YELLOW}{param}{Style.RESET_ALL} | "
            f"{url[:60]}"
        )
