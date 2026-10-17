"""
Unit Tests for Behavior Sentence Extraction Service.
Module: Behavior Detection & ATT&CK Mapping
"""

from backend.app.services.behavior_service import extract_sentences, normalize_text


def _page(number, text):
    return {"page_number": number, "page_text": text, "text": text}


def _sentences(text, page_number=1):
    return [item["sentence"] for item in extract_sentences([_page(page_number, text)])]


def test_attacker_actions_are_kept():
    text = (
        "The actor sent spearphishing emails with a malicious attachment to the victim. "
        "Attackers dumped credentials from LSASS memory using a custom tool. "
        "The malware creates a scheduled task to persist after reboot."
    )
    assert len(_sentences(text)) == 3


def test_defensive_advice_is_rejected():
    text = (
        "Organizations should review their access control policies regularly. "
        "Implement network segmentation to limit lateral movement across the network."
    )
    assert _sentences(text) == []


def test_references_and_meta_sentences_are_rejected():
    text = (
        "[18] NJCCIC Alert: APT10 Adds ZeroLogon Exploitation to TTPs and malware tooling. "
        "Table 1 shows the top vulnerabilities that malicious actors routinely exploit."
    )
    assert _sentences(text) == []


def test_hashes_do_not_block_a_real_behavior_sentence():
    text = (
        "The actor downloaded a JSP webshell with MD5 F8FF5C72E8FFA2112B01802113148BD1 "
        "from the compromised server."
    )
    assert len(_sentences(text)) == 1


def test_source_page_is_recorded_and_duplicates_are_removed():
    sentence = "The actor sent spearphishing emails with a malicious attachment to the victim."
    results = extract_sentences([_page(2, sentence), _page(5, sentence)])
    assert len(results) == 1
    assert results[0]["source_page"] == 2


def test_both_page_text_keys_are_supported():
    sentence = "Attackers dumped credentials from LSASS memory using a custom tool."
    with_text = [{"page_number": 1, "text": sentence}]
    with_page_text = [{"page_number": 1, "page_text": sentence}]
    assert len(extract_sentences(with_text)) == 1
    assert len(extract_sentences(with_page_text)) == 1


def test_empty_input_returns_empty_list():
    assert extract_sentences([]) == []
    assert extract_sentences([_page(1, "   ")]) == []


def test_page_boilerplate_is_removed():
    cleaned = normalize_text("Intro TLP:CLEAR Page 15 of 22 | Product ID: AA23-250A closing")
    assert "TLP" not in cleaned
    assert "Page" not in cleaned
    assert "Product" not in cleaned
    assert cleaned.startswith("Intro")