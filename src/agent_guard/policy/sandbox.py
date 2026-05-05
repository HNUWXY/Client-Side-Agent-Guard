from __future__ import annotations

import os
from typing import Tuple
from urllib.parse import urlparse


class PathSandbox:
    def __init__(self, allowed_prefixes: Tuple[str, ...]):
        self._prefixes = tuple(os.path.abspath(os.path.expanduser(p)) for p in allowed_prefixes)

    def is_allowed(self, path: str) -> bool:
        p = os.path.abspath(os.path.expanduser(path))
        for root in self._prefixes:
            if p == root or p.startswith(root + os.sep):
                return True
        return False


class NetworkSandbox:
    def __init__(self, allowed_hosts: Tuple[str, ...]):
        self._hosts = frozenset(h.lower() for h in allowed_hosts)

    def is_allowed(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
        except Exception:
            return False
        host = (parsed.hostname or "").lower()
        if not host:
            return False
        if host in self._hosts:
            return True
        for h in self._hosts:
            if host.endswith("." + h) or host == h:
                return True
        return False
