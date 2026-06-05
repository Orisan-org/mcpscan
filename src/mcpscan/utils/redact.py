from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit


def mask_value(value: str, keep_prefix: int = 4, keep_suffix: int = 4) -> str:
    if len(value) <= keep_prefix + keep_suffix + 3:
        return "***"
    return f"{value[:keep_prefix]}...{value[-keep_suffix:]}"


def redact_url_credentials(value: str) -> str:
    parsed = urlsplit(value)
    if not parsed.username or not parsed.password or not parsed.hostname:
        return value
    host = parsed.hostname
    if parsed.port:
        host = f"{host}:{parsed.port}"
    netloc = f"{parsed.username}:***@{host}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


def redact_secret(value: str) -> str:
    if "-----BEGIN" in value and "PRIVATE KEY-----" in value:
        return "-----BEGIN PRIVATE KEY-----...redacted..."
    if re.match(r"^[a-z][a-z0-9+.-]*://[^/\s]+:[^@\s]+@", value, re.I):
        return redact_url_credentials(value)
    return mask_value(value)
