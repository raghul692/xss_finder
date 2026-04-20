#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║              XSS FINDER - Professional XSS Scanner           ║
║         For Authorized Penetration Testing Only              ║
╚══════════════════════════════════════════════════════════════╝

Author  : Built for Security Research & Ethical Hacking
Version : 1.0.0
Usage   : python main.py --url http://example.com [options]

DISCLAIMER: Use only on systems you own or have explicit written
permission to test. Unauthorized scanning is illegal.
"""

import argparse
import sys
import os
from colorama import init, Fore, Style

# Initialize colorama for Windows compatibility
init(autoreset=True)

BANNER = f"""
{Fore.RED}
 ██╗  ██╗███████╗███████╗    ███████╗██╗███╗   ██╗██████╗ ███████╗██████╗ 
 ╚██╗██╔╝██╔════╝██╔════╝    ██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
  ╚███╔╝ ███████╗███████╗    █████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
  ██╔██╗ ╚════██║╚════██║    ██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
 ██╔╝ ██╗███████║███████║    ██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║
 ╚═╝  ╚═╝╚══════╝╚══════╝    ╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.YELLOW}  [*] XSS Vulnerability Scanner v1.0  |  For Authorized Testing Only
  [*] Detects: Reflected XSS | Stored XSS | DOM-based XSS
{Style.RESET_ALL}
"""


def parse_arguments():
    """
    Parse command-line arguments using argparse.
    All scan options are configurable here.
    """
    parser = argparse.ArgumentParser(
        prog='xss_finder',
        description='XSS Finder - Professional Cross-Site Scripting Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  Basic scan:
    python main.py --url http://testsite.com

  Deep crawl with 3 levels:
    python main.py --url http://testsite.com --crawl-depth 3

  Use specific payload file:
    python main.py --url http://testsite.com --payloads payloads.txt

  Save JSON report:
    python main.py --url http://testsite.com --output results.json

  Full options:
    python main.py --url http://testsite.com --crawl-depth 2 --payload-type advanced --threads 5 --verbose --output report

  With authentication cookies:
    python main.py --url http://testsite.com --cookies "session=abc123; csrftoken=xyz"

  Verbose mode:
    python main.py --url http://testsite.com --verbose
        """
    )

    # ─── Required ───────────────────────────────────────────────────────────
    parser.add_argument(
        '--url', required=True,
        help='Target URL to scan (e.g., http://example.com)'
    )

    # ─── Crawling Options ────────────────────────────────────────────────────
    crawl_group = parser.add_argument_group('Crawling Options')
    crawl_group.add_argument(
        '--crawl-depth', type=int, default=2, metavar='N',
        help='How deep to crawl links from target (default: 2)'
    )
    crawl_group.add_argument(
        '--no-crawl', action='store_true',
        help='Disable crawling — only scan the given URL'
    )

    # ─── Payload Options ─────────────────────────────────────────────────────
    payload_group = parser.add_argument_group('Payload Options')
    payload_group.add_argument(
        '--payloads', default='payloads.txt', metavar='FILE',
        help='Path to payload file (default: payloads.txt)'
    )
    payload_group.add_argument(
        '--payload-type',
        choices=['basic', 'advanced', 'waf_bypass', 'dom', 'all'],
        default='all',
        help='Which category of payloads to use (default: all)'
    )

    # ─── Output Options ──────────────────────────────────────────────────────
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '--output', metavar='FILE',
        help='Base name for output report (e.g., "report" → report.json + report.txt)'
    )
    output_group.add_argument(
        '--format', dest='report_format',
        choices=['json', 'txt', 'both'], default='both',
        help='Report format to generate (default: both)'
    )

    # ─── Performance Options ─────────────────────────────────────────────────
    perf_group = parser.add_argument_group('Performance Options')
    perf_group.add_argument(
        '--threads', type=int, default=3, metavar='N',
        help='Number of concurrent scanning threads (default: 3)'
    )
    perf_group.add_argument(
        '--timeout', type=int, default=10, metavar='SEC',
        help='HTTP request timeout in seconds (default: 10)'
    )
    perf_group.add_argument(
        '--delay', type=float, default=0.5, metavar='SEC',
        help='Delay between requests to avoid rate-limiting (default: 0.5)'
    )

    # ─── Authentication / Session ────────────────────────────────────────────
    auth_group = parser.add_argument_group('Authentication Options')
    auth_group.add_argument(
        '--cookies', metavar='COOKIE_STRING',
        help='Cookies to send with requests (e.g., "session=abc; token=xyz")'
    )
    auth_group.add_argument(
        '--headers', metavar='JSON',
        help='Extra headers as JSON string (e.g., \'{"X-Auth": "token123"}\')'
    )
    auth_group.add_argument(
        '--user-agent', metavar='UA',
        help='Custom User-Agent string'
    )

    # ─── Advanced Options ────────────────────────────────────────────────────
    adv_group = parser.add_argument_group('Advanced Options')
    adv_group.add_argument(
        '--verbose', '-v', action='store_true',
        help='Enable verbose/debug output'
    )
    adv_group.add_argument(
        '--dom-check', action='store_true',
        help='Enable DOM XSS detection (requires Selenium + browser driver)'
    )

    return parser.parse_args()


def main():
    """
    Main program entry point.
    Validates inputs, then launches the scan engine.
    """
    print(BANNER)

    # Step 1: Parse CLI arguments
    args = parse_arguments()

    # Step 2: Import logger after colorama is initialized
    from utils.logger import Logger
    logger = Logger(verbose=args.verbose)

    # Step 3: Print scan configuration
    logger.section("SCAN CONFIGURATION")
    logger.info(f"Target URL    : {args.url}")
    logger.info(f"Crawl Depth   : {'DISABLED' if args.no_crawl else args.crawl_depth}")
    logger.info(f"Payload File  : {args.payloads}")
    logger.info(f"Payload Type  : {args.payload_type.upper()}")
    logger.info(f"Threads       : {args.threads}")
    logger.info(f"Timeout       : {args.timeout}s")
    logger.info(f"Request Delay : {args.delay}s")
    logger.info(f"Report Format : {args.report_format.upper()}")
    logger.info(f"DOM Check     : {'ENABLED (Selenium)' if args.dom_check else 'DISABLED'}")
    logger.info(f"Verbose Mode  : {'ON' if args.verbose else 'OFF'}")
    print()

    # Step 4: Validate payloads file
    if not os.path.exists(args.payloads):
        logger.error(f"Payloads file not found: '{args.payloads}'")
        logger.info(f"Tip: Create a 'payloads.txt' file in the same directory,")
        logger.info(f"     or specify path with --payloads <file>")
        sys.exit(1)

    # Step 5: Initialize and run the scan engine
    try:
        from scanner.engine import ScanEngine

        engine = ScanEngine(
            target_url=args.url,
            crawl_depth=args.crawl_depth,
            no_crawl=args.no_crawl,
            payloads_file=args.payloads,
            payload_type=args.payload_type,
            output=args.output,
            report_format=args.report_format,
            threads=args.threads,
            timeout=args.timeout,
            delay=args.delay,
            cookies=args.cookies,
            extra_headers=args.headers,
            user_agent=args.user_agent,
            verbose=args.verbose,
            dom_check=args.dom_check,
            logger=logger
        )

        engine.run()

    except KeyboardInterrupt:
        print()
        logger.warning("Scan interrupted by user (Ctrl+C). Exiting cleanly...")
        sys.exit(0)

    except Exception as e:
        logger.error(f"Fatal error during scan: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
