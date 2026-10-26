"""Link Checker - inspects URLs in the email.  (based on Bilal's VirusTotal module)

Offline heuristics always run (raw IP, shorteners, look-alike domains, '@' tricks,
link-text vs href mismatch). VirusTotal reputation is handled by a separate module (virustotal.py).
"""
import re
from urllib.parse import urlparse
from phishguard.core.models import ModuleReport, Severity

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
              "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "rb.gy"}
BRANDS = ["paypal", "netflix", "amazon", "microsoft", "google",
          "apple", "bank", "facebook", "whatsapp", "instagram"]

URL_RE = re.compile(r"https?://[^\s<>\x22\x27)]+", re.I)
ANCHOR_RE = re.compile(r"<a[^>]*href=[\x22\x27]?(https?://[^\x22\x27>\s]+)[^>]*>(.*?)</a>", re.I | re.S)


def _domain(url: str) -> str:
    try:
        net = urlparse(url).netloc.lower()
        return net.split("@")[-1].split(":")[0]
    except Exception:
        return ""


def _is_ip(host: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))


def _lookalike(host: str):
    """Return the brand name if the host looks like a typosquat of it, else None."""
    swaps = {"0": "o", "1": "l", "3": "e", "5": "s", "$": "s"}
    norm = "".join(swaps.get(c, c) for c in host.lower())
    for b in BRANDS:
        if b in norm and host.lower() not in (b + ".com",) and not host.lower().endswith("." + b + ".com"):
            return b
    return None


def _parts(msg):
    plain, html = "", ""
    if msg.is_multipart():
        for p in msg.walk():
            try:
                content = p.get_content()
            except Exception:
                continue
            if p.get_content_type() == "text/plain":
                plain += content + "\n"
            elif p.get_content_type() == "text/html":
                html += content + "\n"
    else:
        try:
            content = msg.get_content()
            if msg.get_content_type() == "text/html":
                html += content
            else:
                plain += content
        except Exception:
            pass
    return plain, html




class LinkDetector:
    """Finds and scores suspicious URLs in an email."""

    def name(self) -> str:
        return "link_analysis"

    def analyze(self, msg) -> ModuleReport:
        plain, html = _parts(msg)
        urls = set(URL_RE.findall(plain)) | set(URL_RE.findall(html))
        flags = []
        worst = 0

        def bump(level):
            nonlocal worst
            worst = max(worst, level)

        for u in urls:
            host = _domain(u)
            if not host:
                continue
            if _is_ip(host):
                flags.append(f"raw IP address URL ({host})"); bump(3)
            if host in SHORTENERS:
                flags.append(f"URL shortener ({host})"); bump(2)
            authority = u.split("://", 1)[-1].split("/", 1)[0]
            if "@" in authority:
                flags.append("'@' trick in URL"); bump(3)
            if host.startswith("xn--") or ".xn--" in host:
                flags.append(f"punycode domain ({host})"); bump(3)
            la = _lookalike(host)
            if la:
                flags.append(f"look-alike of '{la}' ({host})"); bump(3)

        # link text vs real href mismatch (HTML)
        for href, text in ANCHOR_RE.findall(html):
            shown = URL_RE.findall(text)
            if shown and _domain(href) and _domain(shown[0]) and _domain(href) != _domain(shown[0]):
                flags.append(f"link shows {_domain(shown[0])} but goes to {_domain(href)}"); bump(3)


        if not urls:
            return ModuleReport(module=self.name(), passed=True, severity=Severity.INFO,
                                details="No URLs found in the email.")
        if worst == 0:
            return ModuleReport(module=self.name(), passed=True, severity=Severity.INFO,
                                details=f"{len(urls)} URL(s) found, none suspicious.")

        sev = Severity.CRITICAL if worst >= 5 else (Severity.HIGH if worst >= 3 else Severity.WARNING)
        return ModuleReport(module=self.name(), passed=False, severity=sev,
                            details="; ".join(flags[:6]))
