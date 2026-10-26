import os
from phishguard.core.eml import load_eml
from phishguard.core.engine import analyze_file, verdict_for
from phishguard.header.auth_results import AuthResultsDetector
from phishguard.header.reply_mismatch import ReplyMismatchDetector
from phishguard.header.brand_spoofing import BrandSpoofingDetector
from phishguard.links.link_module import LinkDetector

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")
PHISH = os.path.join(SAMPLES, "phishing_sample.eml")
SAFE = os.path.join(SAMPLES, "safe_sample.eml")


def test_phishing_sample_is_phishing():
    _, score, verdict = analyze_file(PHISH)
    assert verdict == "PHISHING"
    assert score >= 5


def test_safe_sample_is_safe():
    _, score, verdict = analyze_file(SAFE)
    assert verdict == "SAFE"
    assert score == 0


def test_auth_module_flags_failure():
    msg = load_eml(PHISH)
    r = AuthResultsDetector().analyze(msg)
    assert r.passed is False


def test_reply_mismatch_flags():
    msg = load_eml(PHISH)
    r = ReplyMismatchDetector().analyze(msg)
    assert r.passed is False


def test_brand_spoofing_flags():
    msg = load_eml(PHISH)
    r = BrandSpoofingDetector().analyze(msg)
    assert r.passed is False


def test_link_module_flags():
    msg = load_eml(PHISH)
    r = LinkDetector().analyze(msg)
    assert r.passed is False


def test_safe_passes_each_header_module():
    msg = load_eml(SAFE)
    assert AuthResultsDetector().analyze(msg).passed
    assert ReplyMismatchDetector().analyze(msg).passed
    assert BrandSpoofingDetector().analyze(msg).passed


def test_verdict_thresholds():
    assert verdict_for(0) == "SAFE"
    assert verdict_for(3) == "SUSPICIOUS"
    assert verdict_for(7) == "PHISHING"


def test_virustotal_skips_without_key(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    from phishguard.links.virustotal import VirusTotalDetector
    msg = load_eml(PHISH)
    r = VirusTotalDetector(api_key="").analyze(msg)
    assert r.passed is True          # skipped, does not break the pipeline
    assert "VirusTotal" in r.details
