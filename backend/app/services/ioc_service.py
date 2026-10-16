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

# Common file extensions and format suffixes that look like domain TLDs to avoid false positives
FILE_EXTENSIONS = {
    # Documents & media
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv", "tsv", "txt",
    "png", "jpg", "jpeg", "gif", "svg", "bmp", "ico",
    # Binaries, archives & drivers
    "exe", "dll", "bin", "iso", "sys", "zip", "rar", "7z", "tar", "gz",
    # Scripts, source code & web templates
    "ps1", "bat", "cmd", "sh", "py", "c", "cpp", "h", "cs", "java", "class",
    "js", "ts", "html", "htm", "css", "vbs", "vbe", "wsf", "hta", "jar", "war",
    "php", "jsp", "jspx", "asp", "aspx", "axd", "ashx", "asmx", "pl", "pm",
    "go", "rb", "rs", "wasm",
    # Configuration, data & certificate formats
    "json", "xml", "yaml", "yml", "cfg", "ini", "log", "tmp", "bak",
    "properties", "conf", "config", "dist", "save", "sample", "backup",
    "pem", "crt", "cer", "key", "pfx", "p12", "stix", "taxii", "hzn",
    # Reconnaissance target configs & proprietary event logs
    "evd", "production", "development", "project", "old", "prod", "local",
}

# Curated reference authorities, government CSIRTs, standard bodies, security research vendors,
# and RFC documentation placeholders that should not be extracted as threat indicators.
REFERENCE_DOMAINS = {
    # US Government & Incident Response Authorities
    "cisa.gov", "cisa.dhs.gov", "us-cert.gov", "fbi.gov", "nsa.gov",
    "defense.gov", "justice.gov", "dni.gov", "energy.gov", "treasury.gov",
    "stopransomware.gov",
    # International Cybersecurity Agencies
    "cyber.gov.au", "cyber.gc.ca", "ncsc.gov.uk", "ncsc.govt.nz",
    "cert.ssi.gouv.fr", "ssi.gouv.fr", "cyber.gouv.fr", "anssi.gouv.fr",
    "cert.europa.eu", "enisa.europa.eu", "bsi.bund.de",
    # Vulnerability, Standards, and IP Registries
    "mitre.org", "cve.org", "nist.gov", "first.org", "iana.org",
    "ietf.org", "rfc-editor.org", "w3.org", "oasis-open.org", "icann.org",
    "arin.net", "ripe.net", "apnic.net", "lacnic.net", "afrinic.net",
    # Major Security Vendors, Threat Portals, and Advisory References
    "microsoft.com", "msrc.microsoft.com", "vmware.com", "citrix.com",
    "atlassian.com", "fortinet.com", "paloaltonetworks.com", "mandiant.com",
    "fireeye.com", "virustotal.com", "symantec.com", "trendmicro.com",
    "crowdstrike.com", "sentinelone.com", "sophos.com", "kaspersky.com",
    "ivanti.com", "qualys.com", "tenable.com", "rapid7.com", "leaseweb.com",
    # Footnote News & Academic Citation Sources
    "washingtonpost.com", "nytimes.com", "reuters.com", "bleepingcomputer.com",
    "therecord.media", "bankinfosecurity.com", "krebsonsecurity.com",
    "darkreading.com", "wikipedia.org", "rand.org", "project2049.net",
    "uscc.gov", "paper.edu.cn", "lw23.com", "hbsh.org", "ecice06.com",
    # RFC 2606 / Documentation Placeholders
    "example.com", "example.net", "example.org", "insecure-org.com",
}

# Dual-use platform hosting services (domains should not be extracted as adversary domain IOCs,
# but specific payload URLs on them may be extracted if pointing to adversary endpoints).
PLATFORM_HOSTING_DOMAINS = {
    "github.com", "raw.githubusercontent.com", "pastebin.com", "gitlab.com",
    "bitbucket.org", "discord.com", "telegram.org", "surge.sh",
}

# Detection prefix pattern for antivirus engine signatures
AV_SIGNATURE_PREFIX = re.compile(
    r"\b(?:Trojan|GrayWare|TR|Backdoor|HackTool|Ransomware|Ransom|Worm|Virus|Exploit|Rootkit|Dropper|Downloader|Infostealer|Spyware|Adware)[/.](?:[A-Za-z0-9_.-]+[/.])?$",
    re.IGNORECASE
)

# Common code method, property, or API scope suffixes that look like domains
CODE_METHOD_SUFFIXES = {
    "deserialize", "getinstance", "getruntime", "getlocalhost", "getinputstream",
    "parseint", "fileno", "trim", "length", "socket", "call", "value", "execute", "read",
}

# Document classification markings
CLASSIFICATION_TLDS = {"clear", "unclass", "restricted", "secret", "confidential", "internal"}

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


def is_reference_domain(domain_str: str) -> bool:
    """
    Checks if a domain belongs to known reference authorities, standards bodies,
    security vendors, documentation examples, or platform hosting providers.
    """
    d = domain_str.lower().strip(".")
    if d in REFERENCE_DOMAINS or d in PLATFORM_HOSTING_DOMAINS:
        return True
    parts = d.split(".")
    for i in range(1, len(parts) - 1):
        parent = ".".join(parts[i:])
        if parent in REFERENCE_DOMAINS or parent in PLATFORM_HOSTING_DOMAINS:
            return True
    return False


def is_platform_hosting_domain(domain_str: str) -> bool:
    """
    Checks if a domain is a shared platform hosting provider (e.g. GitHub, Pastebin)
    where raw payload URLs may exist while the apex domain itself is not an IOC.
    """
    d = domain_str.lower().strip(".")
    if d in PLATFORM_HOSTING_DOMAINS:
        return True
    parts = d.split(".")
    for i in range(1, len(parts) - 1):
        parent = ".".join(parts[i:])
        if parent in PLATFORM_HOSTING_DOMAINS:
            return True
    return False


def is_reference_url(norm_url: str, host: str, raw_match: str = "", context: str = "", line: str = "") -> bool:
    """
    Determines if a URL is a benign reference, advisory, or documentation link.
    Permits specific malware payload/staging URLs, download endpoints, or defanged
    tool/payload URLs accompanied by IOC/threat context on platform hosting services.
    """
    if is_reference_domain(host):
        if is_platform_hosting_domain(host):
            lower_url = norm_url.lower()
            if "/raw/" in lower_url or "/download" in lower_url or "/releases/download" in lower_url:
                return False
            path_part = norm_url.split("://", 1)[-1].split("?", 1)[0].split("#", 1)[0]
            if any(path_part.lower().endswith(f".{ext}") for ext in ("php", "x86_64", "exe", "bin", "sh", "elf", "ps1", "txt", "jsp", "asp", "aspx")):
                return False

            # Explicit negative signals: documentation, guidance, tools, references on the current line or URL path
            check_text = f"{line} {norm_url}" if line else f"{context} {norm_url}"
            if re.search(r"\b(?:doc|docs|documentation|reference|references|guidance|mitigation|remediation|guide|manual|scanner|rule|benchmark|advisory|advisories)\b", check_text, re.IGNORECASE):
                return True

            # Retain platform URLs only when defanging is accompanied by relevant IOC/threat context
            is_defanged = bool(raw_match and re.search(r"hxxp|\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\[:\]", raw_match, re.IGNORECASE))
            has_threat_context = bool(context and re.search(
                r"\b(?:dropped|drops|malware|webshell|backdoor|payload|staged|c2|threat|ioc|iocs|indicator|indicators|exploit|attacker|adversary|observed|implant|trojan)\b",
                context,
                re.IGNORECASE,
            ))
            if is_defanged and has_threat_context:
                return False

            return True
        return True
    return False


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
    Rejects private, loopback, multicast, broadcast, and invalid octets,
    as well as /16 network and broadcast boundaries (ending in .0.0 or .255.255).
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

        # Reject /16 network and broadcast boundaries which are not host addresses
        if (octets[2] == "0" and octets[3] == "0") or (octets[2] == "255" and octets[3] == "255"):
            return False

        return not is_private_ip(ip_str)
    except Exception:
        return False


def is_version_or_ua_ip(match_span: tuple[int, int], line: str, prev_line: str = "") -> bool:
    """
    Detects if an IPv4 match is actually a software build version or browser User-Agent string.
    """
    start, end = match_span
    prefix = line[:start]
    suffix = line[end:]

    # 1. User-Agent / product string (e.g. Chrome/116.0.0.0, Safari/537.36)
    # Exclude unix network device paths like /dev/tcp/ and /dev/udp/
    if re.search(r"(?:Chrome|Safari|Firefox|Edge|Edg|OPR|Opera|AppleWebKit|Gecko|Mozilla|Mobile|MSIE|Trident|Version)/[0-9.]*$", prefix, re.IGNORECASE):
        return True
    if re.search(r"[a-zA-Z]+/[0-9.]*$", prefix) and not re.search(r"/(?:dev|etc|tmp|var|usr|bin)/", prefix, re.IGNORECASE):
        return True

    # 2. Version prefix immediately before digits (e.g. v1.2.3.4, v. 1.2.3.4)
    if re.search(r"(?:\b[vV]\.?\s*)$", prefix):
        return True

    # 3. Version / build keywords preceding candidate (handles lists like 'versions 21.08.0.1, 20.10.0.1')
    ver_kw_match = re.search(r"\b(?:version|versions|ver\.|build|builds|release|rel\.|revision)\b((?:[^\n]{0,80}))$", prefix, re.IGNORECASE)
    if ver_kw_match:
        intervening = ver_kw_match.group(1)
        # Sentence boundary terminates version context
        if not re.search(r"[.!?]\s+", intervening):
            # If intervening text contains network/host/prose words, it transitioned away from the version list
            if not re.search(r"\b(?:server|host|node|ip|address|from|to|at|on|endpoint|connecting|compromised|c2|victim|actor|attacker|deployed|was)\b", intervening, re.IGNORECASE):
                return True

    if re.search(r"\b(?:before|after|prior\s+to|earlier\s+than)\s*$", prefix, re.IGNORECASE):
        return True

    # Check previous wrapped line in table / list context
    if prev_line and prev_line.strip().lower().endswith(("before", "after", "build", "builds", "version", "versions", "release", "prior to", "earlier")):
        return True

    # 4. Version suffix immediately following candidate (e.g. 2.0.0.1 and earlier, 12.1.55.18; version 12.0)
    if re.search(r"^\s*(?:and earlier|and later|or earlier|or later|and above|and below|or above|or below|;\s*version)\b", suffix, re.IGNORECASE):
        return True

    return False


def is_av_signature(match_span: tuple[int, int], line: str) -> bool:
    """
    Detects if a domain match is part of an antivirus threat detection signature
    (e.g., Trojan/Win64.Shelma, GrayWare/Win32.Rozena.j, TR/Crypt.XPACK.Gen7, Vir.IT eXplorer).
    """
    start, end = match_span
    prefix = line[:start]
    suffix = line[end:]
    if AV_SIGNATURE_PREFIX.search(prefix):
        return True
    domain_cand = line[start:end].lower()
    if any(domain_cand.startswith(p) for p in ("win32.", "win64.", "trojan.", "crypt.", "obfuscated.", "hacktool.")):
        return True
    if domain_cand == "vir.it" and suffix.strip().startswith("eXplorer"):
        return True
    return False


def is_method_call(match_span: tuple[int, int], line: str) -> bool:
    """
    Detects if a domain match is followed by function or method invocation parentheses.
    """
    start, end = match_span
    suffix = line[end:]
    if re.search(r"^\s*\(", suffix):
        return True
    return False


def is_email_local_part(match_span: tuple[int, int], line: str) -> bool:
    """
    Detects if a candidate domain match is actually the local-part (username)
    of an email address preceding an '@' symbol (e.g. personal.information.reveal@gmail.com
    or defanged user.name[at]protonmail.com).

    Ensures that dot-delimited email usernames ending in strings that coincide with valid
    gTLDs (e.g. .reveal, .download, .pro, .info) are not falsely extracted as network domains.
    """
    start, end = match_span
    suffix = line[end:]
    # Check if candidate is immediately followed by standard or defanged '@' delimiter
    if re.match(r"^\s*(?:@|\[at\]|\(at\)|\[@\]|\(@\))", suffix, re.IGNORECASE):
        return True
    return False


def normalize_cve(raw_cve: str) -> str:
    """
    Standardizes CVE format and resolves footnote corruption (e.g. CVE-2024-938038 -> CVE-2024-9380).
    """
    cve = raw_cve.upper().replace("_", "-")
    parts = cve.split("-")
    if len(parts) == 3:
        prefix, year, seq = parts
        # If sequence number has 6 or 7 digits and exceeds realistic annual allocations (> 60000)
        if len(seq) >= 6 and int(seq) > 60000:
            # Check if stripping last 2 digits yields a realistic CVE sequence
            candidate_seq = seq[:-2]
            if len(candidate_seq) >= 4 and int(candidate_seq) <= 60000:
                return f"{prefix}-{year}-{candidate_seq}"
            candidate_seq1 = seq[:-1]
            if len(candidate_seq1) >= 4 and int(candidate_seq1) <= 60000:
                return f"{prefix}-{year}-{candidate_seq1}"
    return cve


def is_valid_domain(domain_str: str) -> bool:
    """
    Validates that a candidate string is a plausible domain:
    - Must have at least one dot.
    - TLD must be alphabetic, at least 2 characters, and not a common file extension or classification marking.
    - Must not be an IP address or reference domain.
    - Labels must be alphanumeric with optional hyphens.
    - Must not be a programming method, object property, or package name.
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

    # Validate TLD against file extensions, CVE prefix artifact, or classification markers
    if not tld.isalpha() or len(tld) < 2 or tld in FILE_EXTENSIONS or tld == "cve":
        return False

    # Discard script or binary file extensions occurring in middle labels (e.g. eval-stdin.php.dev)
    if any(l in ("php", "asp", "aspx", "jsp", "jspx", "cgi", "exe", "dll") for l in labels[:-1]):
        return False

    # Discard document classification markings
    if tld in CLASSIFICATION_TLDS and any(domain.startswith(p) for p in ("mar-", "cisa-", "report-")):
        return False

    # Discard code method calls and property suffixes
    if tld in CODE_METHOD_SUFFIXES and len(labels) >= 2:
        return False

    # Discard common code packages
    if any(domain.startswith(pkg) for pkg in ("javax.", "java.", "org.apache.", "com.sun.")):
        return False

    # Discard reference authorities & documentation placeholders
    if is_reference_domain(domain):
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
        prev_line = ""

        for idx, line in enumerate(lines):
            if not line.strip():
                continue

            normalized_line = normalize_defanged(line)

            # 1. Extract CVEs (normalizing footnote concatenation)
            for match in CVE_PATTERN.finditer(normalized_line):
                raw_cve = match.group(0)
                cve_val = normalize_cve(raw_cve)
                key = ("cve", cve_val)
                if key not in seen_iocs:
                    seen_iocs.add(key)
                    extracted_iocs.append({
                        "type": "cve",
                        "value": cve_val,
                        "source_page": page_num,
                        "evidence": extract_evidence_snippet(line, raw_cve),
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
                combined_evidence = line

                # Handle line-wrapped platform URLs where path continues on the next line
                temp_norm = clean_url(normalize_defanged(raw_match))
                hm = re.search(r"https?://([^/:\s]+)", temp_norm, re.IGNORECASE)
                if hm and is_platform_hosting_domain(hm.group(1)):
                    # Only reconstruct if the URL strictly terminates the line with a trailing slash
                    if raw_match.endswith("/") and line.rstrip().endswith(raw_match) and idx + 1 < len(lines):
                        next_l = lines[idx + 1].strip()
                        if next_l and not re.match(r"^(?:https?|hxxps?|ftp)://", next_l, re.IGNORECASE):
                            next_tokens = next_l.split()
                            next_part = next_tokens[0].rstrip(".,;:)'\"]}>")
                            # Valid path continuation must contain a subpath '/' or known file extension
                            is_valid_path = (
                                re.match(r"^[a-zA-Z0-9_\-\./~%]+$", next_part)
                                and ("/" in next_part or any(next_part.lower().endswith(f".{ext}") for ext in ("zip", "tar.gz", "tgz", "bin", "exe", "sh", "py", "php", "txt", "pdf")))
                                and not next_part.lower().startswith(("http", "page", "tlp", "figure", "table", "section", "update"))
                            )
                            # Reject if the next line appears to be an ordinary prose sentence starting with capitalized words
                            if len(next_tokens) > 1 and re.match(r"^[A-Z][a-z]+(?:\s+[a-z]+)+", next_l):
                                is_valid_path = False

                            if is_valid_path:
                                raw_match = raw_match + next_part
                                combined_evidence = f"{line.strip()} {next_l}"

                norm_url = clean_url(normalize_defanged(raw_match))
                # Validate host component
                host_match = re.search(r"https?://([^/:\s]+)", norm_url, re.IGNORECASE)
                if host_match:
                    host = host_match.group(1).lower()
                    if is_valid_ipv4(host) or is_valid_domain(host) or is_reference_domain(host):
                        line_urls_for_masking.append(match.group(0))
                        line_urls_for_masking.append(norm_url)
                        # Exclude benign reference/advisory URLs (checking up to 3 lines of preceding context)
                        context_lines = [l.strip() for l in lines[max(0, idx - 3):idx + 1] if l.strip()]
                        context = " ".join(context_lines)
                        if is_reference_url(norm_url, host, raw_match, context, line):
                            continue
                        key = ("url", norm_url)
                        if key not in seen_iocs:
                            seen_iocs.add(key)
                            extracted_iocs.append({
                                "type": "url",
                                "value": norm_url,
                                "source_page": page_num,
                                "evidence": extract_evidence_snippet(combined_evidence, raw_match),
                            })
                        # Also register host as a domain IOC if it's a domain and not a hosting platform or reference domain
                        if is_valid_domain(host) and not is_platform_hosting_domain(host):
                            d_key = ("domain", host)
                            if d_key not in seen_iocs:
                                seen_iocs.add(d_key)
                                extracted_iocs.append({
                                    "type": "domain",
                                    "value": host,
                                    "source_page": page_num,
                                    "evidence": extract_evidence_snippet(combined_evidence, raw_match),
                                })

            # 6. Extract IPv4 addresses (excluding version numbers and User-Agent strings)
            for match in IPV4_PATTERN.finditer(normalized_line):
                ip_val = match.group(0)
                if is_valid_ipv4(ip_val) and not is_version_or_ua_ip(match.span(), normalized_line, prev_line):
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
                if (
                    is_valid_domain(norm_domain)
                    and not is_av_signature(match.span(), domain_search_line)
                    and not is_method_call(match.span(), domain_search_line)
                    and not is_email_local_part(match.span(), domain_search_line)
                ):
                    key = ("domain", norm_domain)
                    if key not in seen_iocs:
                        seen_iocs.add(key)
                        extracted_iocs.append({
                            "type": "domain",
                            "value": norm_domain,
                            "source_page": page_num,
                            "evidence": extract_evidence_snippet(line, raw_domain),
                        })

            prev_line = line

    return extracted_iocs
