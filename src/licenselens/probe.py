"""Repository probing: resolve a repo's license without burning API quota.

Two channels, chosen per repository:

``html``
    Parse the repository page and the license blob's ``<textarea>``. Needs no
    token and consumes no API budget, so it scales to hundreds of repos and
    survives a black-holed ``raw.githubusercontent.com``.

``api``
    The REST API. Exact, but 60 requests/hour unauthenticated. Used to enrich a
    row with a licence expression, stars, archive state and push date.

The HTML channel is the default for bulk work. The API channel exists because
``license.spdxId`` on the API is sometimes a better labelling than anything in
the file - and because sometimes we genuinely want the metadata.

A note on ``NOASSERTION``: GitHub writes it when its own detector fails. It does
*not* mean "no license". Several repositories tagged ``NOASSERTION`` carry a
perfectly explicit CC BY-SA 4.0. So ``NOASSERTION`` always triggers a text read
rather than a verdict.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .judge import Verdict, judge, judge_expression
from .policy import Decision, Finding, Policy, evaluate
from .sources import (
    LICENSE_FILENAMES,
    Fetcher,
    SourceUnavailable,
    api_json,
    rate_budget,
)
from .text import unescape_markup

RE_STARS_JSON = re.compile(r'"stargazerCount":(\d+)')
RE_FORKS_JSON = re.compile(r'"forkCount":(\d+)')
RE_STARS_LEGACY = re.compile(
    r'id="repo-stars-counter-star"[^>]*aria-label="([\d,]+) users starred'
)
RE_FORKS_LEGACY = re.compile(r'id="repo-network-counter"[^>]*title="([\d,]+)"')
RE_ARCHIVED = re.compile(r'"isArchived":(true|false)')
RE_BRANCH = re.compile(r'"defaultBranch":"([^"]+)"')
RE_CREATED = re.compile(r'"createdAt":"([^"]+)"')
RE_LANG = re.compile(r'itemprop="programmingLanguage">([^<]+)<')
RE_LANG_JSON = re.compile(r'"primaryLanguage":\{"name":"([^"]+)"')

#: GitHub's blob page used to embed the file body in a ``<textarea>``. It no
#: longer does: as of the 2025 React rewrite the body arrives inside the React
#: payload as ``"rawLines":["line","line",...]``. Both forms are supported
#: because the markup is not part of any contract and changes without notice -
#: a scraper pinned to one shape fails silently and reports "no license", which
#: then blocks every dependency. That failure mode is worse than a parse error.
RE_TEXTAREA = re.compile(r"<textarea[^>]*>(.*?)</textarea>", re.S)
RE_RAW_LINES = re.compile(r'"rawLines":\[(.*?)\](?=,"|\})', re.S)

#: ``license.spdxId`` as GitHub itself labels the repository.
RE_SPDX_ID = re.compile(r'"license":\{"spdxId":"([^"]*)"')
RE_SPDX_ID_ALT = re.compile(r'"spdxId":"([^"]+)"')
RE_LICENSE_NAME = re.compile(r'"license":\{"spdxId":"[^"]*","name":"([^"]{2,80})"')

RE_BLOB_LINK = re.compile(
    r'<a[^>]*href="/[^"]*?/blob/[^"]*?(?:LICEN[CS]E|COPYING|UNLICENSE)[^"]*?"[^>]*>\s*(.*?)\s*</a>',
    re.S | re.I,
)
RE_NOT_FOUND = re.compile(r'<title>\s*Page not found', re.I)


def _decode_json_string_literal(raw: str) -> str:
    """Decode a single JSON string literal without invoking the json module.

    The React payload escapes quotes as ``\\"`` because the whole blob is itself
    embedded in a JS string, so lines arrive double-escaped. Two decode passes
    recover the original text in the common case; a final unescape handles the
    single-escaped variant.
    """
    text = raw
    for _ in range(2):
        if text.startswith('"') and text.endswith('"') and len(text) >= 2:
            text = text[1:-1]
        try:
            text = text.encode("utf-8").decode("unicode_escape")
        except (UnicodeDecodeError, UnicodeEncodeError):
            break
        if "\\" not in text:
            break
    return text


def _extract_raw_lines(html: str) -> str:
    """Pull the file body out of GitHub's React payload."""
    match = RE_RAW_LINES.search(html)
    if not match:
        return ""
    blob = match.group(1)
    # Split on commas that separate JSON string literals, respecting the
    # escaped quotes inside each literal.
    lines: list[str] = []
    for piece in re.split(r',(?=")', blob):
        piece = piece.strip().rstrip(",")
        if piece.startswith('"'):
            lines.append(_decode_json_string_literal(piece))
        elif piece:
            lines.append(piece.strip('"'))
    text = "\n".join(lines)
    return text.encode("utf-8", "replace").decode("unicode_escape", "replace") if "\\n" in text else text

#: Link texts that are filenames, not license names. Seeing one of these means
#: GitHub did not recognise the license and just rendered the file name.
_FILENAME_LABELS = {
    "license", "license.md", "license.txt", "licence", "licence.md", "copying",
    "copying.md", "unlicense", "notice", "license-code", "license-code.md",
    "license-apache", "license-mit", "license_ee.md",
}


@dataclass
class RepoRecord:
    repo: str
    channel: str = ""
    stars: int | None = None
    forks: int | None = None
    archived: bool | None = None
    created: str = ""
    language: str = ""
    branch: str = ""
    pushed_at: str = ""
    license_file: str = ""
    github_spdx: str = ""
    verdict: Verdict | None = None
    decision: Decision = Decision.REVIEW
    findings: list[Finding] = field(default_factory=list)
    status: str = "ok"
    error: str = ""

    @property
    def staleness_days(self) -> int | None:
        if not self.pushed_at:
            return None
        try:
            then = datetime.strptime(self.pushed_at[:10], "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            return None
        return (datetime.now(timezone.utc) - then).days

    def to_dict(self) -> dict:
        return {
            "repo": self.repo,
            "channel": self.channel,
            "status": self.status,
            "error": self.error,
            "stars": self.stars,
            "forks": self.forks,
            "archived": self.archived,
            "created": self.created,
            "language": self.language,
            "pushed_at": self.pushed_at,
            "staleness_days": self.staleness_days,
            "license_file": self.license_file,
            "github_spdx": self.github_spdx,
            "decision": self.decision.value,
            "license": self.verdict.to_dict() if self.verdict else None,
            "findings": [f.to_dict() for f in self.findings],
        }


class Prober:
    def __init__(
        self,
        *,
        fetcher: Fetcher | None = None,
        token: str | None = None,
        policy: Policy | None = None,
        delay: float = 0.0,
    ) -> None:
        self.fetcher = fetcher or Fetcher()
        self.token = token
        self.policy = policy or Policy()
        self.delay = delay
        self._html_cache: dict[str, str] = {}

    # -- HTML channel ----------------------------------------------------

    def _repo_page(self, repo: str) -> str:
        if repo in self._html_cache:
            return self._html_cache[repo]
        html = self.fetcher.get(f"https://github.com/{repo}")
        self._html_cache[repo] = html
        return html

    @staticmethod
    def _parse_meta(html: str) -> dict:
        """Read repository metadata, preferring the React payload.

        Both the modern JSON form and the legacy DOM counters are checked, in
        that order, so the tool keeps working across GitHub's A/B states.
        """
        meta: dict = {}
        if match := RE_STARS_JSON.search(html):
            meta["stars"] = int(match.group(1))
        elif match := RE_STARS_LEGACY.search(html):
            meta["stars"] = int(match.group(1).replace(",", ""))

        if match := RE_FORKS_JSON.search(html):
            meta["forks"] = int(match.group(1))
        elif match := RE_FORKS_LEGACY.search(html):
            meta["forks"] = int(match.group(1).replace(",", ""))

        if match := RE_ARCHIVED.search(html):
            meta["archived"] = match.group(1) == "true"
        if match := RE_BRANCH.search(html):
            meta["branch"] = match.group(1)
        if match := RE_CREATED.search(html):
            meta["created"] = match.group(1)[:10]
        if match := RE_LANG.search(html):
            meta["language"] = match.group(1).strip()
        elif match := RE_LANG_JSON.search(html):
            meta["language"] = match.group(1).strip()
        return meta

    @staticmethod
    def _license_label(html: str) -> str:
        """The SPDX id GitHub itself assigns, when it assigns one."""
        for pattern in (RE_SPDX_ID, RE_SPDX_ID_ALT):
            if match := pattern.search(html):
                value = match.group(1).strip()
                if value:
                    return value
        return ""

    @staticmethod
    def _license_name(html: str) -> str:
        match = RE_LICENSE_NAME.search(html)
        return match.group(1).strip() if match else ""

    def _license_candidates(self, repo: str, repo_html: str) -> list[str]:
        """Filenames to try, ordered by likelihood.

        The repository page names the real license file (``LICENSE.txt`` rather
        than the assumed ``LICENSE``), so use it when present and fall back to
        the static list otherwise. This removes a whole class of misses on
        repositories that use a suffixed filename.
        """
        names: list[str] = []
        for match in RE_BLOB_LINK.finditer(repo_html):
            text = re.sub(r"<[^>]+>", "", match.group(1)).strip()
            if text and any(token in text.upper() for token in ("LICEN", "COPYING", "UNLICENSE")):
                if text not in names:
                    names.append(text)
        for name in LICENSE_FILENAMES:
            if name not in names:
                names.append(name)
        return names

    def _license_text_from_blob(self, repo: str, branch: str,
                                repo_html: str = "") -> tuple[str, str]:
        """Read the license body from the blob page.

        This is the reason the HTML channel survives a blocked
        ``raw.githubusercontent.com``: the blob page comes from ``github.com``
        and carries the full file body.
        """
        tried: list[str] = []
        for filename in self._license_candidates(repo, repo_html)[:8]:
            url = f"https://github.com/{repo}/blob/{branch}/{filename}"
            try:
                html = self.fetcher.get(url)
            except SourceUnavailable:
                continue
            tried.append(filename)

            match = RE_TEXTAREA.search(html)
            if match:
                text = unescape_markup(match.group(1)).strip()
                if len(text) > 30:
                    return filename, text

            text = _extract_raw_lines(html)
            if len(text) > 30:
                return filename, text

        if tried:
            raise SourceUnavailable(f"license file found but body unreadable: {tried[:3]}")
        raise SourceUnavailable("no license file at repo root")

    def probe_html(self, repo: str) -> RepoRecord:
        record = RepoRecord(repo=repo, channel="html")
        try:
            html = self._repo_page(repo)
        except SourceUnavailable as exc:
            record.status = "unreachable"
            record.error = str(exc)
            return record

        if RE_NOT_FOUND.search(html):
            record.status = "not-found"
            record.error = "repository does not exist or was renamed"
            return record

        meta = self._parse_meta(html)
        record.stars = meta.get("stars")
        record.forks = meta.get("forks")
        record.archived = meta.get("archived")
        record.branch = meta.get("branch") or "main"
        record.created = meta.get("created", "")
        record.language = meta.get("language", "")
        record.github_spdx = self._license_label(html)

        try:
            filename, text = self._license_text_from_blob(repo, record.branch)
            record.license_file = filename
            record.verdict = judge(text)
        except SourceUnavailable:
            record.license_file = ""
            record.verdict = judge("")

        record.decision, record.findings = evaluate(
            record.verdict,
            self.policy,
            staleness_days=record.staleness_days,
            archived=bool(record.archived),
        )
        return record

    # -- API channel -----------------------------------------------------

    def probe_api(self, repo: str) -> RepoRecord:
        record = RepoRecord(repo=repo, channel="api")
        try:
            data, _ = api_json(f"https://api.github.com/repos/{repo}", self.fetcher, self.token)
        except SourceUnavailable as exc:
            record.status = "unreachable"
            record.error = str(exc)
            return record

        record.stars = data.get("stargazers_count")
        record.forks = data.get("forks_count")
        record.archived = data.get("archived")
        record.created = (data.get("created_at") or "")[:10]
        record.language = data.get("language") or ""
        record.branch = data.get("default_branch") or "main"
        record.pushed_at = (data.get("pushed_at") or "")[:10]
        license_obj = data.get("license") or {}
        record.github_spdx = license_obj.get("spdx_id") or ""

        # NOASSERTION is GitHub admitting it does not know, not a claim that
        # there is no license. Always fall through to reading the text.
        if record.github_spdx and record.github_spdx not in ("NOASSERTION", "Other"):
            try:
                filename, text = self._license_text_from_blob(repo, record.branch)
                record.license_file = filename
                record.verdict = judge(text)
            except SourceUnavailable:
                record.verdict = judge_expression(record.github_spdx)
                record.verdict.warnings.append(
                    "License text unreadable; verdict derived from GitHub's label only."
                )
        else:
            try:
                filename, text = self._license_text_from_blob(repo, record.branch)
                record.license_file = filename
                record.verdict = judge(text)
            except SourceUnavailable:
                record.verdict = judge("")

        record.decision, record.findings = evaluate(
            record.verdict,
            self.policy,
            staleness_days=record.staleness_days,
            archived=bool(record.archived),
        )
        return record

    # -- facade ----------------------------------------------------------

    def probe(self, repo: str, *, channel: str = "auto") -> RepoRecord:
        repo = repo.strip().strip("/")
        if repo.startswith("https://github.com/"):
            repo = repo[len("https://github.com/"):]
        if repo.endswith(".git"):
            repo = repo[:-4]
        if repo.count("/") != 1:
            return RepoRecord(repo=repo, status="invalid",
                              error="expected owner/repo")

        if channel == "api":
            record = self.probe_api(repo)
        elif channel == "html":
            record = self.probe_html(repo)
        else:
            record = self.probe_html(repo)
            if record.status in ("unreachable",) and self.token:
                # The HTML host is down but the API host might not be. This is
                # the reverse of the usual direction and does happen.
                record = self.probe_api(repo)

        if self.delay:
            time.sleep(self.delay)
        return record


def check_budget(fetcher: Fetcher, token: str | None) -> dict:
    return rate_budget(fetcher, token)