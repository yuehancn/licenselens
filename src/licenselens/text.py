"""Text normalization helpers shared by the judge and the fetchers.

The judge is deliberately position-aware, so this module also owns the notion
of a license document's "head": the leading slice where a real title lives.
Everything after that is body text, where cross-references to *other*
licenses appear (GPL-3.0 mentioning the Affero license, LGPL-2.1 quoting the
GPL, and so on).
"""

from __future__ import annotations

import hashlib
import html
import re
import unicodedata

#: How many normalized characters count as the title region.
#: 2500 is comfortably past the preamble of every license we ship a
#: fingerprint for, while staying far away from the cross-reference
#: sections that cause the classic GPL/AGPL and LGPL/GPL mix-ups.
HEAD_CHARS = 2500

_WS = re.compile(r"\s+")
_HTML_TAG = re.compile(r"<[^>]{1,400}>")
_ENTITY = re.compile(r"&(?:#\d{1,7}|#[xX][0-9a-fA-F]{1,6}|[a-zA-Z][a-zA-Z0-9]{1,31});")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def unescape_markup(raw: str) -> str:
    """Turn HTML-ish payloads into plain text.

    GitHub serves LICENSE bodies inside a ``<textarea>`` on the blob page, and
    those bodies are HTML-escaped. Order matters: strip tags first, then
    entities, otherwise ``&lt;year&gt;`` would be eaten by the tag stripper.
    """
    if not raw:
        return ""
    if "<" in raw and ">" in raw:
        raw = _HTML_TAG.sub(" ", raw)
    if "&" in raw:
        raw = _ENTITY.sub(lambda m: html.unescape(m.group(0)), raw)
    return raw


def normalize(raw: str, *, keep_case: bool = False) -> str:
    """Collapse a license document into a single searchable line.

    Unicode is NFKC-folded so that fancy quotes and non-breaking spaces in
    real-world LICENSE files do not defeat substring matching.
    """
    if not raw:
        return ""
    text = unicodedata.normalize("NFKC", raw)
    text = _CTRL.sub(" ", text)
    text = text.replace("\u00a0", " ").replace("\u200b", "")
    text = _WS.sub(" ", text).strip()
    return text if keep_case else text.lower()


def head_of(normalized: str, chars: int = HEAD_CHARS) -> str:
    """The title region of an already-normalized document."""
    return normalized[:chars]


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def first_match(pattern: re.Pattern[str], text: str) -> re.Match[str] | None:
    return pattern.search(text)


def looks_like_license_text(normalized: str) -> bool:
    """Cheap gate: does this look like legal text at all?

    Guards against a LICENSE file that is really a redirect notice, a bare
    copyright line, or an empty placeholder.
    """
    if len(normalized) < 40:
        return False
    markers = (
        "license",
        "licence",
        "copyright",
        "permission is hereby granted",
        "all rights reserved",
        "public domain",
        "terms and conditions",
    )
    return any(m in normalized for m in markers)