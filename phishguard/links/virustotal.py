"""VirusTotal URL reputation check (based on Bilal's original module).

Extracts every URL from the email and checks it against the VirusTotal v3 API.
Requires an API key (env var VT_API_KEY, or passed in) and the 'requests' package.
Without a key or without network, it degrades gracefully to an INFO (skipped) result
so the rest of PhishGuard still runs.
"""
import os
import base64
from phishguard.core.models import ModuleReport, Severity
from phishguard.links.link_module import URL_RE, _parts, _domain

VT_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalDetector:
    def __init__(self, api_key=None, max_urls=4, submit_unknown=True, timeout=10):
        self.api_key = (api_key or os.environ.get("VT_API_KEY", "")).strip()
        self.max_urls = max_urls
        self.submit_unknown = submit_unknown
        self.timeout = timeout

    def name(self) -> str:
        return "virustotal"

    def _urls(self, msg):
        plain, html = _parts(msg)
        return set(URL_RE.findall(plain)) | set(URL_RE.findall(html))

    def analyze(self, msg) -> ModuleReport:
        urls = self._urls(msg)
        if not urls:
            return ModuleReport(module=self.name(), passed=True, severity=Severity.INFO,
                                details="No URLs to check with VirusTotal.")
        if not self.api_key:
            return ModuleReport(module=self.name(), passed=True, severity=Severity.INFO,
                                details="VirusTotal check skipped (set VT_API_KEY to enable).")
        try:
            import requests
        except Exception:
            return ModuleReport(module=self.name(), passed=True, severity=Severity.INFO,
                                details="VirusTotal check skipped ('requests' not installed).")

        headers = {"accept": "application/json", "x-apikey": self.api_key}
        worst_mal = worst_susp = checked = 0
        notes = []

        for url in list(urls)[:self.max_urls]:
            uid = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            try:
                r = requests.get(f"{VT_BASE}/urls/{uid}", headers=headers, timeout=self.timeout)
            except Exception:
                notes.append(f"{_domain(url)}: connection error")
                continue

            if r.status_code == 200:
                stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                m = int(stats.get("malicious", 0))
                s = int(stats.get("suspicious", 0))
                checked += 1
                worst_mal = max(worst_mal, m)
                worst_susp = max(worst_susp, s)
                if m:
                    notes.append(f"{_domain(url)}: {m} engines say MALICIOUS")
                elif s:
                    notes.append(f"{_domain(url)}: {s} engines say suspicious")
                else:
                    notes.append(f"{_domain(url)}: clean")
            elif r.status_code == 404:
                if self.submit_unknown:
                    try:
                        requests.post(f"{VT_BASE}/urls", headers=headers,
                                      data={"url": url}, timeout=self.timeout)
                        notes.append(f"{_domain(url)}: not yet in VirusTotal - submitted for analysis")
                    except Exception:
                        notes.append(f"{_domain(url)}: not in VirusTotal")
                else:
                    notes.append(f"{_domain(url)}: not in VirusTotal")
            elif r.status_code == 429:
                notes.append("VirusTotal rate limit reached (free tier = 4 requests/min)")
                break
            elif r.status_code in (401, 403):
                return ModuleReport(module=self.name(), passed=True, severity=Severity.INFO,
                                    details="VirusTotal check skipped (invalid or unauthorized API key).")
            else:
                notes.append(f"VirusTotal API error {r.status_code}")
                break

        summary = "; ".join(notes[:6]) if notes else f"{checked} URL(s) checked, none flagged."
        if worst_mal > 0:
            return ModuleReport(module=self.name(), passed=False, severity=Severity.CRITICAL,
                                details="VirusTotal: " + summary)
        if worst_susp > 0:
            return ModuleReport(module=self.name(), passed=False, severity=Severity.HIGH,
                                details="VirusTotal: " + summary)
        return ModuleReport(module=self.name(), passed=True, severity=Severity.INFO,
                            details="VirusTotal: " + summary)
