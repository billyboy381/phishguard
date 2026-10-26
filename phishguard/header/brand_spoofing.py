"""Check 3 - Display-name brand spoofing.  (developed by Bilal)"""
import re
from email.utils import parseaddr
from phishguard.core.models import ModuleReport, Severity


class BrandSpoofingDetector:
    """Detects brand name spoofing in the From display name where the domain doesn't match."""

    KNOWN_BRANDS = {
        "paypal": ["paypal.com", "paypal.co.uk"],
        "netflix": ["netflix.com"],
        "amazon": ["amazon.com", "amazon.co.uk", "amazon.ca"],
        "microsoft": ["microsoft.com", "live.com", "outlook.com"],
        "google": ["google.com", "googlemail.com"],
        "apple": ["apple.com", "icloud.com"],
    }

    def name(self) -> str:
        return "brand_name_spoofing"

    def analyze(self, msg) -> ModuleReport:
        from_header = msg.get("From", "")
        display_name, email_address = parseaddr(from_header)

        if not display_name or not email_address:
            return ModuleReport(
                module=self.name(), passed=True, severity=Severity.INFO,
                details="No display name or email found to analyze for brand spoofing.",
            )

        display_lower = display_name.lower()
        sender_domain = email_address.split("@")[-1].lower() if "@" in email_address else ""

        matched_brand = None
        official_domains = []
        for brand, domains in self.KNOWN_BRANDS.items():
            if re.search(r"\b" + re.escape(brand) + r"\b", display_lower):
                matched_brand = brand
                official_domains = domains
                break

        if matched_brand and sender_domain not in official_domains:
            return ModuleReport(
                module=self.name(), passed=False, severity=Severity.HIGH,
                details=f"Potential brand spoofing: display name mentions '{matched_brand}', "
                        f"but sender domain '{sender_domain}' is not an authorized {matched_brand} domain.",
            )

        return ModuleReport(
            module=self.name(), passed=True, severity=Severity.INFO,
            details="No unauthorized brand spoofing detected in display name.",
        )
