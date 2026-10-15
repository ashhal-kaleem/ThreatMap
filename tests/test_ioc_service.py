"""
Unit Tests for Deterministic IOC Extraction Service.
Module: PDF Processing & IOC Intelligence
"""

from backend.app.services.ioc_service import (
    PageText,
    clean_url,
    extract_iocs,
    is_private_ip,
    is_valid_domain,
    is_valid_ipv4,
    normalize_defanged,
)


def test_normalize_defanged():
    assert normalize_defanged("192[.]0[.]2[.]1") == "192.0.2.1"
    assert normalize_defanged("malicious(.)example(.)com") == "malicious.example.com"
    assert normalize_defanged("evil{.}org") == "evil.org"
    assert normalize_defanged("hxxps[:]//evil[.]com/gate") == "https://evil.com/gate"
    assert normalize_defanged("hxxp://insecure[dot]org") == "http://insecure.org"
    assert normalize_defanged("attacker[at]c2[.]net") == "attacker@c2.net"


def test_ipv4_validation():
    # Public & test IPs should be valid
    assert is_valid_ipv4("198.51.100.1") is True
    assert is_valid_ipv4("203.0.113.50") is True
    assert is_valid_ipv4("8.8.8.8") is True

    # RFC 1918 Private, loopback, link-local, multicast, and broadcast IPs should be filtered out
    assert is_valid_ipv4("192.168.1.1") is False
    assert is_valid_ipv4("10.0.0.1") is False
    assert is_valid_ipv4("172.16.5.4") is False
    assert is_valid_ipv4("127.0.0.1") is False
    assert is_valid_ipv4("169.254.10.5") is False
    assert is_valid_ipv4("224.0.0.1") is False
    assert is_valid_ipv4("255.255.255.255") is False

    # Invalid octets or numbers
    assert is_valid_ipv4("999.1.1.1") is False
    assert is_valid_ipv4("1.2.3.4.5") is False
    assert is_valid_ipv4("01.2.3.4") is False
    assert is_valid_ipv4("not_an_ip") is False


def test_ipv4_version_string_rejection():
    # Test strings like version numbers 1.2.3.4.5 are not extracted as IPs
    pages = [
        {
            "page_number": 1,
            "page_text": "Release version 1.2.3.4.5 was deployed. The actual C2 was 198.51.100.99.",
        }
    ]
    iocs = extract_iocs(pages)
    ips = [i["value"] for i in iocs if i["type"] == "ipv4"]
    assert "1.2.3.4" not in ips
    assert "198.51.100.99" in ips


def test_domain_validation():
    # Valid domains
    assert is_valid_domain("malicious-c2.com") is True
    assert is_valid_domain("sub.domain.threat.org") is True
    assert is_valid_domain("update.evil.xyz") is True

    # Exclude IP addresses
    assert is_valid_domain("192.0.2.1") is False

    # Exclude common file extensions
    assert is_valid_domain("report.pdf") is False
    assert is_valid_domain("payload.exe") is False
    assert is_valid_domain("document.docx") is False
    assert is_valid_domain("script.ps1") is False

    # Invalid domain syntax
    assert is_valid_domain("-bad.com") is False
    assert is_valid_domain("no_tld") is False


def test_defanged_domains_extraction():
    pages = [
        {
            "page_number": 1,
            "page_text": "Attacker domains: evil[.]com, backup(.)net, and c2{.}org were registered.",
        }
    ]
    iocs = extract_iocs(pages)
    domains = [i["value"] for i in iocs if i["type"] == "domain"]
    assert "evil.com" in domains
    assert "backup.net" in domains
    assert "c2.org" in domains


def test_cve_extraction():
    pages = [
        {
            "page_number": 1,
            "page_text": "The adversary leveraged cve-2023-38831, CVE_2021_44228, and CVE-2020-0601 to gain execution.",
        }
    ]
    iocs = extract_iocs(pages)
    cves = [i for i in iocs if i["type"] == "cve"]

    assert len(cves) == 3
    assert cves[0]["value"] == "CVE-2023-38831"
    assert cves[0]["source_page"] == 1
    assert "cve-2023-38831" in cves[0]["evidence"].lower()
    assert cves[1]["value"] == "CVE-2021-44228"
    assert cves[2]["value"] == "CVE-2020-0601"


def test_hash_extraction_separation():
    # Test MD5, SHA1, and SHA256 in the same text without substring collisions
    md5_hash = "d41d8cd98f00b204e9800998ecf8427e"
    sha1_hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    pages = [
        {
            "page_number": 2,
            "page_text": f"Hashes recovered:\nMD5: {md5_hash.upper()}\nSHA-1: {sha1_hash}\nSHA-256: {sha256_hash}",
        }
    ]
    iocs = extract_iocs(pages)

    md5_results = [i for i in iocs if i["type"] == "md5"]
    sha1_results = [i for i in iocs if i["type"] == "sha1"]
    sha256_results = [i for i in iocs if i["type"] == "sha256"]

    assert len(md5_results) == 1
    assert md5_results[0]["value"] == md5_hash
    assert md5_results[0]["source_page"] == 2

    assert len(sha1_results) == 1
    assert sha1_results[0]["value"] == sha1_hash

    assert len(sha256_results) == 1
    assert sha256_results[0]["value"] == sha256_hash


def test_url_and_defanging_extraction():
    pages = [
        {
            "page_number": 3,
            "page_text": "Stager downloaded from hxxps[:]//evil-cdn[.]com/payload.bin and beaconed to http://threat.net:8080/gate.",
        }
    ]
    iocs = extract_iocs(pages)

    urls = [i for i in iocs if i["type"] == "url"]
    domains = [i for i in iocs if i["type"] == "domain"]

    assert any(u["value"] == "https://evil-cdn.com/payload.bin" for u in urls)
    assert any(u["value"] == "http://threat.net:8080/gate" for u in urls)
    assert urls[0]["source_page"] == 3
    assert any(d["value"] == "evil-cdn.com" for d in domains)


def test_ipv4_defanging_and_private_filtering():
    pages = [
        {
            "page_number": 4,
            "page_text": "Attacker IP: 198.51.100[.]22 was active. Internal probe from 192.168.1[.]50 was discarded.",
        }
    ]
    iocs = extract_iocs(pages)
    ips = [i for i in iocs if i["type"] == "ipv4"]

    assert len(ips) == 1
    assert ips[0]["value"] == "198.51.100.22"
    assert ips[0]["source_page"] == 4
    assert "198.51.100[.]22" in ips[0]["evidence"] or "198.51.100.22" in ips[0]["evidence"]


def test_page_text_backward_compatibility():
    # Test that both 'page_text' and 'text' keys work seamlessly
    pages_with_page_text = [{"page_number": 1, "page_text": "IOC: 198.51.100.10"}]
    pages_with_legacy_text = [{"page_number": 1, "text": "IOC: 198.51.100.20"}]

    iocs1 = extract_iocs(pages_with_page_text)
    iocs2 = extract_iocs(pages_with_legacy_text)

    assert iocs1[0]["value"] == "198.51.100.10"
    assert iocs2[0]["value"] == "198.51.100.20"


def test_deduplication_across_pages():
    pages = [
        {
            "page_number": 1,
            "page_text": "Initial discovery of C2 domain: bad-actor[.]com",
        },
        {
            "page_number": 2,
            "page_text": "Secondary beacon sent to bad-actor.com again.",
        },
    ]
    iocs = extract_iocs(pages)
    domains = [i for i in iocs if i["type"] == "domain" and i["value"] == "bad-actor.com"]

    # Must be deduplicated to exactly one entry, preserving the first occurrence page
    assert len(domains) == 1
    assert domains[0]["source_page"] == 1


def test_defanged_url_path_domain_masking():
    # Defanged URL with a domain-like path segment
    pages = [
        {
            "page_number": 1,
            "page_text": "Payload retrieved from hxxps[:]//evil.com/download/sub.payload-host.org/setup.bin directly.",
        }
    ]
    iocs = extract_iocs(pages)
    urls = [i for i in iocs if i["type"] == "url"]
    domains = [i for i in iocs if i["type"] == "domain"]

    assert len(urls) == 1
    assert urls[0]["value"] == "https://evil.com/download/sub.payload-host.org/setup.bin"

    # evil.com should be extracted as the URL host domain
    assert any(d["value"] == "evil.com" for d in domains)
    # The path segment 'sub.payload-host.org' must NOT be extracted as a false domain IOC
    assert not any(d["value"] == "sub.payload-host.org" for d in domains)


def test_short_defanged_ip_evidence_centering():
    # Long line with short defanged IP near the end
    prefix = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam. Adversary fallback IP was "
    pages = [
        {
            "page_number": 1,
            "page_text": prefix + "1.1.1[.]1 and proceeded to exfiltrate database records.",
        }
    ]
    iocs = extract_iocs(pages)
    ips = [i for i in iocs if i["type"] == "ipv4"]

    assert len(ips) == 1
    assert ips[0]["value"] == "1.1.1.1"
    # Evidence must contain the indicator and be centered around it, not just the start of line
    assert "1.1.1[.]1" in ips[0]["evidence"] or "1.1.1.1" in ips[0]["evidence"]
