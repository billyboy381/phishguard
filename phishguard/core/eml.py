"""Loading an .eml file and pulling out the body text."""
import email
import re
from email import policy


def load_eml(path):
    """Read an .eml file from disk into an email message object."""
    with open(path, "rb") as f:
        return email.message_from_binary_file(f, policy=policy.default)


def load_eml_string(raw: str):
    """Parse a raw email string into a message object."""
    return email.message_from_string(raw, policy=policy.default)


def _strip_html(html: str) -> str:
    text = re.sub(r"(?is)<(script|style).*?</\1>", " ", html)
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def get_body_text(msg) -> str:
    """Return the readable body text (plain text + stripped HTML)."""
    parts = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            try:
                content = part.get_content()
            except Exception:
                continue
            if ctype == "text/plain":
                parts.append(content)
            elif ctype == "text/html":
                parts.append(_strip_html(content))
    else:
        try:
            content = msg.get_content()
            if msg.get_content_type() == "text/html":
                parts.append(_strip_html(content))
            else:
                parts.append(content)
        except Exception:
            pass
    return "\n".join(p for p in parts if p).strip()
