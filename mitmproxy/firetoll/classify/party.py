"""First-party vs third-party is a computed property, not a list: compare
the request host's eTLD+1 against Referer/Origin (and, in the future, the
attributed app's "home" domain).
"""

from __future__ import annotations

import ipaddress
from typing import Literal
from urllib.parse import urlsplit

from publicsuffix2 import get_sld

Party = Literal["first-party", "third-party", "unknown"]


def etld1(host: str) -> str:
    """The registrable domain ("effective TLD + 1") for `host`, e.g.
    `sub.example.co.uk` -> `example.co.uk`. IP literals are returned as-is -
    `get_sld` has no notion of a registrable domain for them."""
    if not host:
        return host
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    return get_sld(host) or host


def classify_party(
    request_host: str, *, referer: str | None = None, origin: str | None = None
) -> Party:
    request_etld1 = etld1(request_host)
    for value in (origin, referer):
        if not value:
            continue
        other_host = urlsplit(value).hostname
        if not other_host:
            continue
        return "first-party" if etld1(other_host) == request_etld1 else "third-party"
    return "unknown"
