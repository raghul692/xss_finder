"""
utils/helpers.py
─────────────────────────────────────────────────────────────────
General Helper / Utility Functions
─────────────────────────────────────────────────────────────────
Shared utility functions used across multiple modules:
  - URL normalization
  - Cookie string parsing
  - Header JSON parsing
  - Page fetching
  - String sanitization
"""

import json
import re
from urllib.parse import urlparse, urlunparse


def normalize_url(url):
    """
    Ensure the URL has a scheme (http/https) and is properly formatted.
    Strips trailing slashes for consistency.

    Examples:
        "example.com"         → "http://example.com"
        "https://example.com/"→ "https://example.com"
        "http://example.com"  → "http://example.com"

    Args:
        url (str): Input URL from user

    Returns:
        str: Normalized URL
    """
    url = url.strip()

    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    # Parse and reconstruct cleanly
    parsed = urlparse(url)

    # Remove trailing slash from path (unless it's just "/")
    path = parsed.path.rstrip('/') or ''

    normalized = urlunparse((
        parsed.scheme,
        parsed.netloc,
        path,
        parsed.params,
        parsed.query,
        ''   # Remove fragment
    ))

    return normalized


def parse_cookies(cookie_string):
    """
    Parse a cookie string into a dict for use with requests.

    Accepts format: "name1=value1; name2=value2"

    Args:
        cookie_string (str): Raw cookie string from CLI --cookies argument

    Returns:
        dict: Cookie name → value mapping

    Example:
        "session=abc123; token=xyz789"
        → {'session': 'abc123', 'token': 'xyz789'}
    """
    if not cookie_string:
        return {}

    cookies = {}
    for part in cookie_string.split(';'):
        part = part.strip()
        if '=' in part:
            name, _, value = part.partition('=')
            cookies[name.strip()] = value.strip()
        elif part:
            # Cookie with no value (rare but valid)
            cookies[part] = ''

    return cookies


def parse_headers(headers_json):
    """
    Parse a JSON string into a dict of HTTP headers.

    Args:
        headers_json (str): JSON string from CLI --headers argument
                            e.g. '{"X-Auth-Token": "abc", "X-Custom": "test"}'

    Returns:
        dict: Header name → value mapping, or empty dict on error
    """
    if not headers_json:
        return {}

    try:
        parsed = json.loads(headers_json)
        if not isinstance(parsed, dict):
            return {}
        return {str(k): str(v) for k, v in parsed.items()}
    except json.JSONDecodeError as e:
        # Return empty dict silently — logger isn't available here
        return {}


def is_same_domain(url1, url2):
    """
    Check if two URLs belong to the same domain (netloc).

    Args:
        url1 (str): First URL
        url2 (str): Second URL

    Returns:
        bool: True if same domain
    """
    return urlparse(url1).netloc == urlparse(url2).netloc


def sanitize_for_filename(text, max_length=50):
    """
    Convert a string into a safe filename by removing/replacing invalid characters.

    Args:
        text       (str): Input string (e.g., a URL)
        max_length (int): Maximum length of output

    Returns:
        str: Sanitized filename-safe string
    """
    # Remove scheme
    text = re.sub(r'^https?://', '', text)
    # Replace invalid filename characters with underscores
    text = re.sub(r'[^\w\-]', '_', text)
    # Collapse multiple underscores
    text = re.sub(r'_+', '_', text)
    # Trim and limit length
    return text.strip('_')[:max_length]


def truncate(text, max_len=100, suffix='...'):
    """
    Truncate a string to max_len characters, appending suffix if truncated.

    Args:
        text    (str): Input string
        max_len (int): Maximum character count
        suffix  (str): Appended when truncated

    Returns:
        str: Possibly truncated string
    """
    if len(text) <= max_len:
        return text
    return text[:max_len - len(suffix)] + suffix


def extract_domain(url):
    """
    Extract the domain/netloc from a URL.

    Args:
        url (str): Full URL

    Returns:
        str: Domain part (netloc)
    """
    return urlparse(url).netloc


def is_valid_url(url):
    """
    Check if a string is a valid HTTP/HTTPS URL.

    Args:
        url (str): Input string to validate

    Returns:
        bool: True if valid
    """
    try:
        parsed = urlparse(url)
        return parsed.scheme in ('http', 'https') and bool(parsed.netloc)
    except Exception:
        return False
