"""The PhishGuard engine - runs every module and produces a verdict."""
from phishguard.core.eml import load_eml, load_eml_string
from phishguard.header.auth_results import AuthResultsDetector
from phishguard.header.reply_mismatch import ReplyMismatchDetector
from phishguard.header.brand_spoofing import BrandSpoofingDetector
from phishguard.links.link_module import LinkDetector
from phishguard.links.virustotal import VirusTotalDetector
from phishguard.content.content_model import ContentDetector

# All detection modules, grouped by the three parts of an email.
MODULES = [
    AuthResultsDetector(),      # header
    ReplyMismatchDetector(),    # header  (Bilal)
    BrandSpoofingDetector(),    # header  (Bilal)
    LinkDetector(),             # links   (Bilal) - offline heuristics
    VirusTotalDetector(),       # links   (Bilal) - VirusTotal reputation
    ContentDetector(),          # content (ML)
]

# Verdict thresholds (sum of risk weights from failed modules)
PHISHING_AT = 5
SUSPICIOUS_AT = 2


def verdict_for(score: int) -> str:
    if score >= PHISHING_AT:
        return "PHISHING"
    if score >= SUSPICIOUS_AT:
        return "SUSPICIOUS"
    return "SAFE"


def analyze_message(msg):
    """Run every module on a parsed message. Returns (reports, score, verdict)."""
    reports = [m.analyze(msg) for m in MODULES]
    score = sum(r.score for r in reports)
    return reports, score, verdict_for(score)


def analyze_file(path):
    """Analyze an .eml file on disk."""
    return analyze_message(load_eml(path))


def analyze_string(raw: str):
    """Analyze a raw email string."""
    return analyze_message(load_eml_string(raw))
