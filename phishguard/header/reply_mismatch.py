"""Check 2 - Sender vs Reply-To mismatch.  (developed by Bilal)"""
from email.utils import parseaddr
from phishguard.core.models import ModuleReport, Severity


class ReplyMismatchDetector:
    """Detects mismatches between the From header domain and the Reply-To header domain."""

    def name(self) -> str:
        return "reply_to_mismatch"

    def analyze(self, msg) -> ModuleReport:
        from_header = msg.get("From", "")
        reply_to_header = msg.get("Reply-To", "")

        _, from_email = parseaddr(from_header)
        _, reply_to_email = parseaddr(reply_to_header)

        if not reply_to_email:
            return ModuleReport(
                module=self.name(), passed=True, severity=Severity.INFO,
                details="No Reply-To header specified; replies will go to the sender.",
            )

        from_domain = from_email.split("@")[-1].lower() if "@" in from_email else ""
        reply_to_domain = reply_to_email.split("@")[-1].lower() if "@" in reply_to_email else ""

        if from_domain and reply_to_domain and from_domain != reply_to_domain:
            return ModuleReport(
                module=self.name(), passed=False, severity=Severity.WARNING,
                details=f"Reply-To domain ({reply_to_domain}) does not match From domain ({from_domain}).",
            )

        return ModuleReport(
            module=self.name(), passed=True, severity=Severity.INFO,
            details=f"Reply-To domain matches From domain ({from_domain}).",
        )
