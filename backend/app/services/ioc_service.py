"""
IOC Extraction Service for ThreatMap Lite.
Module: PDF Processing & IOC Intelligence

Responsibilities:
- Extract Indicators of Compromise (IOCs) using deterministic regex logic:
  * IPv4 addresses (excluding RFC 1918 private, loopback, link-local, multicast, and broadcast ranges)
  * Domains (valid TLD structure, excluding common file extensions and URL paths)
  * URLs (http/https protocols, valid host structure)
  * Hashes: MD5 (32 hex), SHA1 (40 hex), SHA256 (64 hex)
  * CVE identifiers (CVE-YYYY-NNNNN)
- Normalize defanged indicators ([.], (.), {.}, [dot], hxxp, hxxps, [at], [:], etc.).
- Validate extracted values and discard false positives.
- Deduplicate IOCs while preserving source_page and evidence context snippets.
- Strictly deterministic; no LLM or external calls.
"""

import ipaddress
import re
from typing import TypedDict

# Interface contract defined in phases.md
class PageText(TypedDict):
    page_number: int
    page_text: str  # Matches report_pages.page_text
    text: str       # Alias for backward compatibility


class ExtractedIOC(TypedDict):
    type: str         # 'ipv4' | 'domain' | 'url' | 'md5' | 'sha1' | 'sha256' | 'cve'
    value: str        # Normalized, refanged value (e.g. 1.1.1.1, https://evil.com)
    source_page: int  # Source page number
    evidence: str     # Surrounding sentence or context snippet


# RFC 1918, loopback, link-local, multicast, and reserved/broadcast ranges to exclude
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),  # Multicast
    ipaddress.ip_network("240.0.0.0/4"),  # Reserved / Broadcast (includes 255.255.255.255)
]

# Common file extensions that look like domain TLDs to avoid false positives
FILE_EXTENSIONS = {
    "pdf", "exe", "dll", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "zip", "rar", "7z", "tar", "gz", "ps1", "bat", "sh", "py", "c",
    "cpp", "h", "json", "xml", "yaml", "yml", "csv", "tsv", "txt",
    "png", "jpg", "jpeg", "gif", "svg", "bin", "iso", "cfg", "ini",
    "log", "tmp", "bak", "sys", "vbs", "js", "html", "htm", "css",
}

# Regex patterns
CVE_PATTERN = re.compile(r"\bCVE[-_](?:199\d|20\d{2})[-_]\d{4,7}\b", re.IGNORECASE)
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")

# Strict IPv4 regex: rejects version strings (e.g. 1.2.3.4.5) while allowing sentence-ending periods
IPV4_PATTERN = re.compile(r"(?<![\d.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?!\.\d)(?!\d)")

# URL pattern matching standard and defanged protocols
URL_RAW_PATTERN = re.compile(
    r"\b(?:https?|hxxps?)(?:\[:\]|:)?//[^\s<>'\"{}|\\^`]+",
    re.IGNORECASE
)

# Domain pattern matching standard and defanged dots
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\.))+"
    r"[a-zA-Z]{2,24}\b",
    re.IGNORECASE
)


def normalize_defanged(text: str) -> str:
    """
    Normalizes defanged syntax into standard internet notation:
    - hxxp://, hxxps://, hXXp[:]// -> http://, https://
    - [.], (.), {.}, [dot], (dot) -> .
    - [:], (:) -> :
    - [at], (@), {@} -> @
    """
    if not text:
        return ""

    s = text

    # Defanged protocol
    s = re.sub(r"\bhxxps?(?:\[:\]|:)?//", lambda m: "https://" if "s" in m.group(0).lower() else "http://", s, flags=re.IGNORECASE)
    s = re.sub(r"\[:\]|\(:\)", ":", s)

    # Defanged dots
    s = re.sub(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", ".", s, flags=re.IGNORECASE)

    # Defanged at
    s = re.sub(r"\[at\]|\(at\)|\[@\]|\(@\)", "@", s, flags=re.IGNORECASE)

    return s


def is_private_ip(ip_str: str) -> bool:
    """
    Checks if an IPv4 address belongs to RFC 1918 private, loopback, link-local,
    multicast, or non-routable reserved ranges.
    """
    try:
        addr = ipaddress.IPv4Address(ip_str)
        if (
            addr.is_multicast
            or addr.is_reserved
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_unspecified
        ):
            return True
        return any(addr in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return True


def is_valid_ipv4(ip_str: str) -> bool:
    """
    Validates that a string is a valid routable IPv4 address.
    Rejects private, loopback, multicast, broadcast, and invalid octets.
    """
    try:
        octets = ip_str.split(".")
        if len(octets) != 4:
            return False
        for octet in octets:
            num = int(octet)
            if not 0 <= num <= 255:
                return False
            if len(octet) > 1 and octet.startswith("0"):
                return False  # No leading zeros like 01.02.03.04

        return not is_private_ip(ip_str)
    except Exception:
        return False


def is_valid_domain(domain_str: str) -> bool:
    """
    Validates that a candidate string is a plausible domain:
    - Must have at least one dot.
    - TLD must be alphabetic, at least 2 characters, and not a common file extension.
    - Must not be an IP address.
    - Labels must be alphanumeric with optional hyphens.
    """
    domain = domain_str.lower().strip(".")
    if "." not in domain or len(domain) > 253:
        return False

    # Discard if it parses as an IP address
    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        pass

    labels = domain.split(".")
    tld = labels[-1]

    # Validate TLD
    if not tld.isalpha() or len(tld) < 2 or tld in FILE_EXTENSIONS:
        return False

    # Validate each label
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not re.match(r"^[a-z0-9\-]+$", label):
            return False

    # Discard if all labels are pure digits
    if all(l.isdigit() for l in labels[:-1]):
        return False

    return True


def clean_url(url_str: str) -> str:
    """
    Cleans trailing punctuation, parentheses, brackets, or quotes from a URL.
    """
    cleaned = url_str.rstrip(".,;:)'\"]}>")
    return cleaned


def extract_evidence_snippet(line: str, match_str: str, max_length: int = 180) -> str:
    """
    Extracts a contextual snippet surrounding the matched indicator from the line.
    Handles defanged and normalized search tokens safely.
    """
    clean_line = " ".join(line.split()).strip()
    if len(clean_line) <= max_length:
        return clean_line

    pos = clean_line.find(match_str)
    if pos == -1:
        # Check case-insensitive match
        pos = clean_line.lower().find(match_str.lower())

    if pos == -1:
        # If match_str was defanged or normalized (e.g. 198.51.100.1 from 198.51.100[.]1)
        core_tokens = [t for t in re.split(r"[.:/\-_]", match_str) if len(t) >= 2] or [t for t in re.split(r"[.:/\-_]", match_str) if t]
        for token in core_tokens:
            token_pos = clean_line.lower().find(token.lower())
            if token_pos != -1:
                pos = token_pos
                break

    if pos == -1:
        return clean_line[:max_length] + "..."

    half = max_length // 2
    start = max(0, pos - half)
    end = min(len(clean_line), pos + len(match_str) + half)

    snippet = clean_line[start:end].strip()
    if start > 0:
        snippet = "..." + snippet
    if end < len(clean_line):
        snippet = snippet + "..."

    return snippet


def extract_iocs(pages: list[PageText]) -> list[ExtractedIOC]:
    """
    Deterministically extracts, normalizes, validates, and deduplicates IOCs from page text.
    
    Args:
        pages: List of dicts with 'page_number' and 'page_text' (or 'text').
        
    Returns:
        List of dicts: {"type": str, "value": str, "source_page": int, "evidence": str}
    """
    extracted_iocs: list[ExtractedIOC] = []
    seen_iocs: set[tuple[str, str]] = set()

    for page_entry in pages:
        page_num = page_entry.get("page_number", 1)
        raw_text = page_entry.get("page_text") or page_entry.get("text") or ""
        if not raw_text:
            continue

        lines = raw_text.splitlines()

        for line in lines:
            if not line.strip():
                continue

            normalized_line = normalize_defanged(line)

            # 1. Extract CVEs
            for match in CVE_PATTERN.finditer(normalized_line):
                cve_val = match.group(0).upper().replace("_", "-")
                key = ("cve", cve_val)
                if key not in seen_iocs:
                    seen_iocs.add(key)
                    extracted_iocs.append({
                        "type": "cve",
                        "value": cve_val,
                        "source_page": page_num,
                        "evidence": extract_evidence_snippet(line, match.group(0)),
                    })

            # 2. Extract SHA256 hashes (64 hex characters)
            for match in SHA256_PATTERN.finditer(normalized_line):
                sha256_val = match.group(0).lower()
                if len(set(sha256_val)) <= 1:
                    continue  # Ignore trivial runs like 000000000...
                key = ("sha256", sha256_val)
                if key not in seen_iocs:
                    seen_iocs.add(key)
                    extracted_iocs.append({
                        "type": "sha256",
                        "value": sha256_val,
                        "source_page": page_num,
                        "evidence": extract_evidence_snippet(line, match.group(0)),
                    })

            # 3. Extract SHA1 hashes (40 hex characters)
            for match in SHA1_PATTERN.finditer(normalized_line):
                sha1_val = match.group(0).lower()
                if len(set(sha1_val)) <= 1:
                    continue
                key = ("sha1", sha1_val)
                if key not in seen_iocs:
                    seen_iocs.add(key)
                    extracted_iocs.append({
                        "type": "sha1",
                        "value": sha1_val,
                        "source_page": page_num,
                        "evidence": extract_evidence_snippet(line, match.group(0)),
                    })

            # 4. Extract MD5 hashes (32 hex characters)
            for match in MD5_PATTERN.finditer(normalized_line):
                md5_val = match.group(0).lower()
                if len(set(md5_val)) <= 1:
                    continue
                key = ("md5", md5_val)
                if key not in seen_iocs:
                    seen_iocs.add(key)
                    extracted_iocs.append({
                        "type": "md5",
                        "value": md5_val,
                        "source_page": page_num,
                        "evidence": extract_evidence_snippet(line, match.group(0)),
                    })

            # 5. Extract URLs
            line_urls_for_masking = []
            for match in URL_RAW_PATTERN.finditer(line):
                raw_match = match.group(0)
                norm_url = clean_url(normalize_defanged(raw_match))
                # Validate host component
                host_match = re.search(r"https?://([^/:\s]+)", norm_url, re.IGNORECASE)
                if host_match:
                    host = host_match.group(1).lower()
                    if is_valid_ipv4(host) or is_valid_domain(host):
                        key = ("url", norm_url)
                        line_urls_for_masking.append(raw_match)
                        line_urls_for_masking.append(norm_url)
                        if key not in seen_iocs:
                            seen_iocs.add(key)
                            extracted_iocs.append({
                                "type": "url",
                                "value": norm_url,
                                "source_page": page_num,
                                "evidence": extract_evidence_snippet(line, raw_match),
                            })
                        # Also register host as a domain IOC if it's a domain
                        if is_valid_domain(host):
                            d_key = ("domain", host)
                            if d_key not in seen_iocs:
                                seen_iocs.add(d_key)
                                extracted_iocs.append({
                                    "type": "domain",
                                    "value": host,
                                    "source_page": page_num,
                                    "evidence": extract_evidence_snippet(line, raw_match),
                                })

            # 6. Extract IPv4 addresses
            for match in IPV4_PATTERN.finditer(normalized_line):
                ip_val = match.group(0)
                if is_valid_ipv4(ip_val):
                    key = ("ipv4", ip_val)
                    if key not in seen_iocs:
                        seen_iocs.add(key)
                        extracted_iocs.append({
                            "type": "ipv4",
                            "value": ip_val,
                            "source_page": page_num,
                            "evidence": extract_evidence_snippet(line, ip_val),
                        })

            # 7. Extract Domains
            # Mask out URL path components from domain search to avoid matching path segments like /file.domain.org
            domain_search_line = line
            for u in line_urls_for_masking:
                domain_search_line = domain_search_line.replace(u, " ")

            for match in DOMAIN_PATTERN.finditer(domain_search_line):
                raw_domain = match.group(0)
                norm_domain = normalize_defanged(raw_domain).lower().strip(".")
                if is_valid_domain(norm_domain):
                    key = ("domain", norm_domain)
                    if key not in seen_iocs:
                        seen_iocs.add(key)
                        extracted_iocs.append({
                            "type": "domain",
                            "value": norm_domain,
                            "source_page": page_num,
                            "evidence": extract_evidence_snippet(line, raw_domain),
                        })

    return extracted_iocs
