import re
from typing import TypedDict

import spacy


class PageText(TypedDict):
    page_number: int
    page_text: str
    text: str


class BehaviorSentence(TypedDict):
    sentence: str
    source_page: int


MODEL_NAME = "en_core_web_sm"
MIN_WORDS = 6
MAX_WORDS = 60
MIN_LETTERS = 25
MIN_ALPHA_RATIO = 0.65
MIN_STOP_RATIO = 0.15
MAX_CVE_IDS = 2
MAX_UPPER_RATIO = 0.6

ACTION_LEMMAS = {
    "abuse", "access", "add", "archive", "attach", "attempt", "authenticate",
    "beacon", "begin", "bypass", "call", "capture", "change", "clear",
    "collect", "communicate", "compress", "compromise", "conduct",
    "configure", "connect", "convince", "copy", "crack", "create", "decrypt",
    "delete", "deliver", "deploy", "disable", "download", "drop", "dump",
    "elevate", "encode", "encrypt", "enumerate", "escalate", "establish",
    "evade", "execute", "exfiltrate", "exploit", "extract", "gain", "harvest",
    "hide", "identify", "inject", "install", "invoke", "launch", "leverage",
    "load", "lure", "masquerade", "modify", "move", "obfuscate", "obtain",
    "open", "overwrite", "perform", "persist", "phish", "pivot", "provide",
    "query", "read", "redirect", "register", "relay", "remove", "retrieve",
    "run", "scan", "send", "set", "spawn", "spread", "stage", "steal", "stop",
    "target", "terminate", "trick", "trigger", "tunnel", "upload", "use",
    "wipe", "write",
}

SECURITY_STEMS = (
    "malware", "malicious", "payload", "backdoor", "ransom", "credential",
    "password", "powershell", "cmd.exe", ".exe", "command", "registry",
    "scheduled task", "lsass", "c2", "beacon", "phish", "attachment", "macro",
    "exploit", "vulnerab", "remote", "rdp", "smb", "wmi", "dll", "executable",
    "script", "persist", "privilege", "lateral", "exfiltrat", "encrypt",
    "decrypt", "domain controller", "active directory", "vpn", "implant",
    "shell", "trojan", "dropper", "loader", "token", "hash", "keylog",
    "tunnel", "proxy", "webshell", "admin", "account", "server", "actor",
    "attacker", "adversar", "scan", "traversal", "intrusion", "compromis",
)

DEFENSIVE_STARTS = {
    "apply", "audit", "block", "configure", "consider", "deploy", "disable",
    "enable", "ensure", "if", "implement", "keep", "limit", "maintain",
    "monitor", "patch", "prioritize", "remove", "require", "restrict",
    "review", "segment", "test", "update", "use", "verify",
}

ADVICE_PATTERN = re.compile(
    r"\b(should|recommend|recommends|recommended|encourage|encourages|urge|urges"
    r"|must|ensure|review|consider|implement|prioritize|prioritise|upgrade"
    r"|remediate|remediation|mitigate|mitigation|mitigations|guidance"
    r"|best practices?|see|refer)\b",
    re.IGNORECASE,
)
META_PATTERN = re.compile(
    r"\b(sections? below|table \d+ shows|the following table|this advisory|this report)\b",
    re.IGNORECASE,
)
REFERENCE_MARKER = re.compile(r"\[\d{1,3}\]|\bwww\.", re.IGNORECASE)
CVE_PATTERN = re.compile(r"\bCVE[-\s]\d{4}-\d{4,7}\b", re.IGNORECASE)
IOC_PATTERN = re.compile(
    r"(?:hxxps?|https?|ftp)://\S+"
    r"|\b\d{1,3}(?:\[?\.\]?\d{1,3}){3}\b"
    r"|\b[a-fA-F0-9]{32,64}\b"
    r"|\b[\w-]+(?:\[\.\][\w-]+)+\b",
    re.IGNORECASE,
)
FIRST_WORD_PATTERN = re.compile(r"^[^A-Za-z]*([A-Za-z]+)")
BOILERPLATE_PATTERN = re.compile(
    r"TLP\s*:\s*(?:CLEAR|WHITE|GREEN|AMBER(?:\+STRICT)?|RED)"
    r"|Page\s*\|?\s*\d+\s+of\s+\d+"
    r"|Product ID\s*:\s*AA\d{2}-\d{3}[A-Z]?"
    r"|CISA\s*\|\s*FBI\s*\|\s*[A-Z]+"
    r"|UNCLASSIFIED\s*/\s*NON CLASSIFI\S+",
    re.IGNORECASE,
)
HYPHEN_BREAK = re.compile(r"(?<=[a-z])-\s*\n\s*(?=[a-z])")
WHITESPACE = re.compile(r"\s+")

_nlp = None


def get_nlp():
    global _nlp
    if _nlp is None:
        _nlp = spacy.load(MODEL_NAME, disable=["ner"])
        _nlp.max_length = 2_000_000
    return _nlp


def normalize_text(text: str) -> str:
    text = HYPHEN_BREAK.sub("", text)
    text = BOILERPLATE_PATTERN.sub(" ", text)
    return WHITESPACE.sub(" ", text).strip()


def is_heading_like(text: str) -> bool:
    words = re.findall(r"[A-Za-z]{2,}", text)
    if len(words) < 4:
        return False
    upper = sum(word.isupper() for word in words)
    return upper / len(words) > MAX_UPPER_RATIO


def passes_filter(span) -> bool:
    text = span.text
    scrubbed = IOC_PATTERN.sub(" ", text)

    word_count = len(scrubbed.split())
    if not MIN_WORDS <= word_count <= MAX_WORDS:
        return False

    letters = sum(char.isalpha() for char in scrubbed)
    compact_length = max(len(scrubbed.replace(" ", "")), 1)
    if letters < MIN_LETTERS or letters / compact_length < MIN_ALPHA_RATIO:
        return False

    if (
        REFERENCE_MARKER.search(text)
        or ADVICE_PATTERN.search(text)
        or META_PATTERN.search(text)
    ):
        return False

    if len(CVE_PATTERN.findall(text)) > MAX_CVE_IDS:
        return False

    if is_heading_like(scrubbed):
        return False

    first = FIRST_WORD_PATTERN.match(text)
    if first and first.group(1).lower() in DEFENSIVE_STARTS:
        return False

    alpha_tokens = [token for token in span if token.is_alpha]
    if not alpha_tokens:
        return False
    stop_ratio = sum(token.is_stop for token in alpha_tokens) / len(alpha_tokens)
    if stop_ratio < MIN_STOP_RATIO:
        return False

    lowered = text.lower()
    if not any(stem in lowered for stem in SECURITY_STEMS):
        return False

    return any(
        token.pos_ == "VERB" and token.lemma_.lower() in ACTION_LEMMAS
        for token in span
    )


def iter_sentence_records(pages: list[PageText]) -> list[dict]:
    nlp = get_nlp()
    records = []
    for page in pages:
        raw_text = page.get("page_text") or page.get("text") or ""
        text = normalize_text(raw_text)
        if not text:
            continue
        for span in nlp(text).sents:
            sentence = span.text.strip()
            if not any(char.isalpha() for char in sentence):
                continue
            records.append(
                {
                    "sentence": sentence,
                    "source_page": page["page_number"],
                    "passes_filter": passes_filter(span),
                }
            )
    return records


def extract_sentences(pages: list[PageText]) -> list[BehaviorSentence]:
    seen = set()
    results: list[BehaviorSentence] = []
    for record in iter_sentence_records(pages):
        if not record["passes_filter"]:
            continue
        key = record["sentence"].lower()
        if key in seen:
            continue
        seen.add(key)
        results.append(
            {"sentence": record["sentence"], "source_page": record["source_page"]}
        )
    return results