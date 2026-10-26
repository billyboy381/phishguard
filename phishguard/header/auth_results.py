"""Check 1 - SPF / DKIM / DMARC authentication results (the Envelope Checker)."""
from phishguard.core.models import ModuleReport, Severity


class AuthResultsDetector:
    """Reads the Authentication-Results header and flags SPF/DKIM/DMARC failures."""

    def name(self) -> str:
        return "auth_results"

    def analyze(self, msg) -> ModuleReport:
        ar = (msg.get("Authentication-Results", "") or "").lower()

        if not ar:
            return ModuleReport(
                module=self.name(), passed=True, severity=Severity.INFO,
                details="No Authentication-Results header present (cannot verify SPF/DKIM/DMARC).",
            )

        failed = [k for k in ("spf", "dkim", "dmarc")
                  if (k + "=fail" in ar or k + "=softfail" in ar)]

        if failed:
            severity = Severity.CRITICAL if len(failed) >= 3 else Severity.HIGH
            return ModuleReport(
                module=self.name(), passed=False, severity=severity,
                details=f"Authentication failed: {', '.join(f.upper() for f in failed)}. "
                        "The email could not prove it came from the domain it claims.",
            )

        return ModuleReport(
            module=self.name(), passed=True, severity=Severity.INFO,
            details="SPF/DKIM/DMARC did not fail.",
        )
