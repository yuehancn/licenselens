"""Resilient HTTP access for license lookups.

Two things here are the whole point of the module:

1. **Dual channel.** ``raw.githubusercontent.com`` is blocked or black-holed on
   plenty of corporate and regional networks, while ``github.com`` itself keeps
   working. Every license read therefore has a primary channel (raw) and a
   fallback channel (the blob page's ``<textarea>``), and the fallback is used
   automatically instead of surfacing a network error.

2. **Circuit breaker.** A black-holed host does not fail fast: the TCP connect
   hangs until the socket timeout expires. Naively retrying a filename list
   against such a host turns a 24-repo audit into an hour of silence. Once a
   host trips the breaker, every further request to it returns instantly, so
   the caller degrades to the other channel in microseconds.

Nothing in here needs an API token. Tokens only raise rate limits.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

USER_AGENT = "licenselens/0.1 (+https://github.com/yuehancn/licenselens)"

#: Filenames that carry a license, in priority order. Variants matter:
#: ``LICENSE-CODE`` and ``LICENSE_EE.md`` are real and are missed by
#: directory-listing heuristics.
LICENSE_FILENAMES: tuple[str, ...] = (
    "LICENSE",
    "LICENSE.md",
    "LICENSE.txt",
    "LICENCE",
    "LICENCE.md",
    "COPYING",
    "COPYING.md",
    "COPYING.txt",
    "LICENSE-CODE",
    "LICENSE-CODE.md",
    "LICENSE-APACHE",
    "LICENSE-MIT",
    "UNLICENSE",
    "NOTICE",
)

#: Filenames we must NOT treat as the project's own license. A vendored copy
#: under ``vendor/`` says nothing about the parent repository.
NOT_A_PROJECT_LICENSE = (
    "node_modules/",
    "vendor/",
    "third_party/",
    "third-party/",
    "deps/",
    "external/",
)


class SourceUnavailable(RuntimeError):
    """Raised when every channel for a resource is exhausted or broken."""


@dataclass
class HostHealth:
    consecutive_failures: int = 0
    opened_at: float | None = None
    last_error: str = ""

    def is_open(self, cooldown: float) -> bool:
        if self.opened_at is None:
            return False
        return (time.monotonic() - self.opened_at) < cooldown


@dataclass
class FetchStats:
    requests: int = 0
    cache_hits: int = 0
    failures: int = 0
    breaker_trips: int = 0
    by_host: dict[str, int] = field(default_factory=dict)


class Fetcher:
    """Timeout-bounded, cache-backed, breaker-protected text fetcher."""

    def __init__(
        self,
        *,
        timeout: float = 15.0,
        cache_dir: str | os.PathLike[str] | None = None,
        breaker_threshold: int = 2,
        breaker_cooldown: float = 300.0,
    ) -> None:
        self.timeout = timeout
        self.breaker_threshold = breaker_threshold
        self.breaker_cooldown = breaker_cooldown
        self.cache_dir = Path(cache_dir).expanduser() if cache_dir else None
        self.stats = FetchStats()
        self._hosts: dict[str, HostHealth] = {}
        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

    # -- breaker ---------------------------------------------------------

    def host_state(self, url: str) -> HostHealth:
        host = urllib.parse.urlsplit(url).netloc.lower()
        return self._hosts.setdefault(host, HostHealth())

    def _allowed(self, url: str) -> bool:
        state = self.host_state(url)
        if state.is_open(self.breaker_cooldown):
            return False
        if state.is_open(self.breaker_cooldown) is False and state.opened_at is not None:
            # Cooldown elapsed: half-open, allow one probe.
            state.opened_at = None
            state.consecutive_failures = 0
        return True

    def _record(self, url: str, ok: bool, error: str = "") -> None:
        state = self.host_state(url)
        if ok:
            state.consecutive_failures = 0
            state.opened_at = None
            state.last_error = ""
            return
        state.consecutive_failures += 1
        state.last_error = error
        if state.consecutive_failures >= self.breaker_threshold and state.opened_at is None:
            state.opened_at = time.monotonic()
            self.stats.breaker_trips += 1

    def tripped_hosts(self) -> list[str]:
        return [h for h, s in self._hosts.items() if s.opened_at is not None]

    # -- cache -----------------------------------------------------------

    def _cache_path(self, url: str) -> Path | None:
        if not self.cache_dir:
            return None
        safe = urllib.parse.quote(url, safe="").replace("%", "_")[:180]
        return self.cache_dir / f"{safe}.txt"

    def _cache_read(self, url: str) -> str | None:
        path = self._cache_path(url)
        if path and path.exists() and path.stat().st_size > 0:
            self.stats.cache_hits += 1
            return path.read_text(encoding="utf-8", errors="replace")
        return None

    def _cache_write(self, url: str, text: str) -> None:
        path = self._cache_path(url)
        if path:
            try:
                path.write_text(text, encoding="utf-8")
            except OSError:
                pass

    # -- fetch -----------------------------------------------------------

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> str:
        cached = self._cache_read(url)
        if cached is not None:
            return cached

        if not self._allowed(url):
            self.stats.by_host[urllib.parse.urlsplit(url).netloc] = (
                self.stats.by_host.get(urllib.parse.urlsplit(url).netloc, 0) + 1
            )
            raise SourceUnavailable(f"circuit open for {url}")

        request_headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        if headers:
            request_headers.update(headers)

        self.stats.requests += 1
        host = urllib.parse.urlsplit(url).netloc
        self.stats.by_host[host] = self.stats.by_host.get(host, 0) + 1

        last: Exception | None = None
        for attempt in range(2):
            try:
                request = urllib.request.Request(url, headers=request_headers)
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    text = response.read().decode("utf-8", "replace")
                self._record(url, True)
                self._cache_write(url, text)
                return text
            except urllib.error.HTTPError as exc:
                # A 404 is a definitive answer, not a transport failure: the
                # host is healthy, the path simply does not exist.
                if exc.code in (404, 410, 451):
                    self._record(url, True)
                    raise SourceUnavailable(f"HTTP {exc.code} for {url}") from exc
                last = exc
                self._record(url, False, f"HTTP {exc.code}")
                if exc.code in (400, 401, 403):
                    raise SourceUnavailable(f"HTTP {exc.code} for {url}") from exc
            except Exception as exc:  # noqa: BLE001 - transport layer, all fatal here
                last = exc
                self._record(url, False, type(exc).__name__)
            if attempt == 0 and not self.host_state(url).is_open(self.breaker_cooldown):
                time.sleep(0.3)

        self.stats.failures += 1
        raise SourceUnavailable(f"{type(last).__name__}: {url}") from last


def resolve_token() -> tuple[str | None, str]:
    """Find a GitHub token without ever prompting the user.

    Order: explicit env vars, then the ``gh`` CLI if it is already logged in.
    A missing token is not an error - it only lowers the API budget from
    5000/h to 60/h, and the HTML channel needs no budget at all.
    """
    for var in ("LICENSELENS_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"):
        value = os.environ.get(var)
        if value and value.strip():
            return value.strip(), f"env:{var}"

    exe = shutil.which("gh")
    candidates = [exe] if exe else []
    candidates += [
        r"C:\AI\gh\bin\gh.exe",
        "/usr/local/bin/gh",
        "/opt/homebrew/bin/gh",
    ]
    for candidate in candidates:
        if not candidate:
            continue
        try:
            result = subprocess.run(
                [candidate, "auth", "token"],
                capture_output=True,
                text=True,
                timeout=12,
                encoding="utf-8",
                errors="replace",
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip(), f"gh:{candidate}"
    return None, "none"


def _api_headers(token: str | None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def api_json(url: str, fetcher: Fetcher, token: str | None) -> tuple[dict, dict]:
    """GET a GitHub API resource as JSON. Raises SourceUnavailable on failure."""
    raw = fetcher.get(url, headers=_api_headers(token))
    payload = json.loads(raw)
    return payload, {}


def rate_budget(fetcher: Fetcher, token: str | None) -> dict:
    try:
        data, _ = api_json("https://api.github.com/rate_limit", fetcher, token)
        core = data.get("resources", {}).get("core", {})
        return {
            "limit": core.get("limit"),
            "remaining": core.get("remaining"),
            "reset": core.get("reset"),
        }
    except Exception:  # noqa: BLE001
        return {"limit": None, "remaining": None, "reset": None}