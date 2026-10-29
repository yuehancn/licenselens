"""The license judge: position-weighted fingerprint matching.

Why not plain substring matching in a hand-written ``if/elif`` chain?
Because that approach fails on real license texts, and the failures are
expensive rather than obvious:

* **GPL-3.0 mentions the Affero license.** Section 13 is literally titled
  "Use with the GNU Affero General Public License". A judge that greps the whole
  document for "Affero General Public License" concludes AGPL-3.0, which is a
  network-copyleft license -- a materially harsher answer than GPL-3.0.
* **LGPL-2.1 quotes the GPL** in its preamble. Whole-document matching for
  "GNU General Public License" concludes GPL, losing the "Lesser" and turning a
  weak-copyleft library into a strong-copyleft one.
* **Ordering is load-bearing.** BSD and MIT texts legitimately contain
  "All rights reserved". If the "all rights reserved" rule is evaluated before
  the specific-license rules, permissive licenses get labelled as
  all-rights-reserved, i.e. unusable.

The fix is structural instead of sequential:

1. Every signal carries a **region**. Title signals may only fire inside the
   document head; incidental mentions in the body cannot promote a license.
2. Every signal carries a **weight**. Title evidence outweighs body evidence by
   more than an order of magnitude, so a stray cross-reference cannot flip a
   verdict even inside the head.
3. The verdict needs a **minimum score**, a **margin** over the runner-up, and
   the runner-up is always reported. Ambiguity becomes visible data rather than
   a silently wrong label.

The result is order-independent: rules can be listed in any order, and adding a
new license cannot change an existing verdict.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

from .text import HEAD_CHARS, head_of, looks_like_license_text, normalize

# --------------------------------------------------------------------------
# Vocabulary
# --------------------------------------------------------------------------

#: Commercial-use verdicts, from most to least permissive.
COMMERCIAL_OK = "allowed"
COMMERCIAL_CONDITIONAL = "conditional"
COMMERCIAL_FORBIDDEN = "forbidden"
COMMERCIAL_UNKNOWN = "unknown"

#: Copyleft strength. ``none`` = permissive; ``file`` = weak/file-level;
#: ``project`` = strong; ``network`` = strong plus the network clause.
COPYLEFT_NONE = "none"
COPYLEFT_FILE = "file"
COPYLEFT_PROJECT = "project"
COPYLEFT_NETWORK = "network"

#: Weight constants. Title evidence must swamp body evidence.
W_TITLE = 100       # The license names itself as the title.
W_STRONG = 55       # A long, unforgettable operative sentence.
W_MEDIUM = 30       # A distinctive phrase.
W_WEAK = 12         # A common legal phrase; only useful in aggregate.

REGION_HEAD = "head"
REGION_BODY = "body"


@dataclass(frozen=True)
class Signal:
    """One weighted piece of evidence for a candidate license."""

    pattern: re.Pattern[str]
    weight: int
    region: str = REGION_BODY
    note: str = ""


def sig(pattern: str, weight: int, region: str = REGION_BODY, note: str = "",
        flags: int = re.I) -> Signal:
    return Signal(re.compile(pattern, flags), weight, region, note)


@dataclass(frozen=True)
class Profile:
    """Everything the tool knows about one license family."""

    spdx_id: str
    name: str
    signals: tuple[Signal, ...]
    commercial: str = COMMERCIAL_OK
    copyleft: str = COPYLEFT_NONE
    obligations: tuple[str, ...] = ()
    patent_grant: bool = False
    trademark_grant: bool = False
    network_clause: bool = False
    spdx_expression: str = ""

    @property
    def requires_source_disclosure(self) -> bool:
        return self.copyleft != COPYLEFT_NONE

    def to_dict(self) -> dict:
        return {
            "spdx_id": self.spdx_id,
            "name": self.name,
            "commercial": self.commercial,
            "copyleft": self.copyleft,
            "obligations": list(self.obligations),
            "patent_grant": self.patent_grant,
            "trademark_grant": self.trademark_grant,
            "network_clause": self.network_clause,
        }


# --------------------------------------------------------------------------
# Fingerprints
# --------------------------------------------------------------------------

_PERMISSIVE_NOTE = "Attribution only; keep the copyright notice and license text."

PROFILES: tuple[Profile, ...] = (
    Profile(
        spdx_id="MIT",
        name="MIT License",
        signals=(
            sig(r"\bmit license\b", W_TITLE, REGION_HEAD),
            sig(r"permission is hereby granted,\s*free of charge,\s*to any person "
                r"obtaining a copy", W_STRONG),
            sig(r"without limitation the rights to use,\s*copy,\s*modify,\s*merge,"
                r"\s*publish,\s*distribute,\s*sublicense", W_STRONG),
            sig(r"the software is provided\s*[\"\u201c]?as is", W_MEDIUM),
            sig(r"shall be included in all copies or substantial portions", W_MEDIUM),
        ),
        commercial=COMMERCIAL_OK,
        obligations=(_PERMISSIVE_NOTE, "State changes if you redistribute modified sources (good practice, not a license term)."),
    ),
    Profile(
        spdx_id="ISC",
        name="ISC License",
        signals=(
            sig(r"\bisc license\b", W_TITLE, REGION_HEAD),
            sig(r"permission to use,\s*copy,\s*modify,\s*and/?or distribute this "
                r"software for any purpose", W_STRONG),
            sig(r"provided that the above copyright notice and this permission "
                r"notice appear in all copies", W_MEDIUM),
        ),
        commercial=COMMERCIAL_OK,
        obligations=(_PERMISSIVE_NOTE,),
    ),
    Profile(
        spdx_id="BSD-2-Clause",
        name='BSD 2-Clause "Simplified" License',
        signals=(
            sig(r"\bbsd 2-clause\b", W_TITLE, REGION_HEAD),
            # NOTE ON SHARED CLAUSES: clauses 1 and 2 are identical in BSD-2 and
            # BSD-3, so they must stay at low weight. If they outscore the
            # distinguishing clause 3, every BSD-3 file resolves to BSD-2 -
            # which is what happened to pallets/flask (145 vs 140) before this
            # was tuned. Only clauses unique to a variant may carry W_STRONG.
            sig(r"redistribution and use in source and binary forms,\s*with or "
                r"without modification,\s*are permitted provided that", W_MEDIUM),
            sig(r"redistributions of source code must retain the above copyright",
                W_MEDIUM),
            sig(r"redistributions in binary form must reproduce the above copyright",
                W_MEDIUM),
            # Absence-based disambiguation: BSD-2 has exactly two conditions and
            # no endorsement clause. See _disambiguate_bsd().
        ),
        commercial=COMMERCIAL_OK,
        obligations=(_PERMISSIVE_NOTE,),
    ),
    Profile(
        spdx_id="BSD-3-Clause",
        name='BSD 3-Clause "New" or "Revised" License',
        signals=(
            sig(r"\bbsd 3-clause\b", W_TITLE, REGION_HEAD),
            # Clause 3 is the sole textual difference from BSD-2 and it is
            # phrased several ways in the wild; each spelling is a strong signal.
            sig(r"neither the name of (?:the copyright holder|[\w.\-]+(?:,\s*inc\.?)?)",
                W_STRONG),
            sig(r"\bendorse or promote products derived from this software\b",
                W_STRONG),
            sig(r"the names? of (?:its|the) contributors may (?:not|nor) be used to "
                r"endorse", W_STRONG),
            sig(r"without specific prior written permission", W_MEDIUM),
            sig(r"redistribution and use in source and binary forms,\s*with or "
                r"without modification,\s*are permitted provided that", W_MEDIUM),
        ),
        commercial=COMMERCIAL_OK,
        obligations=(
            _PERMISSIVE_NOTE,
            "Must not use the authors' names to endorse or promote derived products without permission.",
        ),
    ),
    Profile(
        spdx_id="Apache-2.0",
        name="Apache License 2.0",
        signals=(
            sig(r"\bapache license\b[\s\S]{0,40}?\bversion 2\.0\b", W_TITLE, REGION_HEAD),
            sig(r"terms and conditions for use,\s*reproduction,\s*and distribution",
                W_STRONG),
            sig(r"licensed under the apache license,\s*version 2\.0", W_STRONG),
            sig(r"apache\.org/licenses/license-2\.0", W_MEDIUM),
            sig(r"you must give any other recipients of the work or derivative "
                r"works a copy of this license", W_MEDIUM),
            sig(r"grant of patent license", W_MEDIUM),
        ),
        commercial=COMMERCIAL_OK,
        patent_grant=True,
        trademark_grant=False,
        obligations=(
            _PERMISSIVE_NOTE,
            "Must ship a copy of the license, keep NOTICE contents, and mark modified files.",
            "Includes an express patent grant; patent litigation terminates it.",
            "Trademark rights are explicitly NOT granted.",
        ),
    ),
    Profile(
        spdx_id="MPL-2.0",
        name="Mozilla Public License 2.0",
        signals=(
            sig(r"\bmozilla public license\b[\s\S]{0,30}?2\.0", W_TITLE, REGION_HEAD),
            sig(r"mozilla public license,\s*v(?:ersion)?\.?\s*2\.0", W_STRONG),
            sig(r"exhibit a\s*-\s*source code form license notice", W_MEDIUM),
            sig(r"covered software", W_WEAK),
            sig(r"incompatible with secondary licenses", W_MEDIUM),
        ),
        commercial=COMMERCIAL_OK,
        copyleft=COPYLEFT_FILE,
        obligations=(
            "File-level copyleft: only modified MPL-covered files must be published as source.",
            "Larger works may stay proprietary as long as they are not themselves MPL-covered.",
        ),
    ),
    Profile(
        spdx_id="EPL-2.0",
        name="Eclipse Public License 2.0",
        signals=(
            sig(r"\beclipse public license\b[\s\S]{0,30}?v?(?:ersion)?\.?\s*2\.0",
                W_TITLE, REGION_HEAD),
            sig(r"eclipse public license\s*-\s*v\s*2\.0", W_STRONG),
            sig(r"commercial distributors of the program", W_MEDIUM),
        ),
        commercial=COMMERCIAL_OK,
        copyleft=COPYLEFT_FILE,
        obligations=(
            "Weak copyleft on modified EPL modules; must offer source for those modules.",
            "Includes a patent retaliation clause.",
        ),
    ),
    Profile(
        spdx_id="LGPL-3.0",
        name="GNU Lesser General Public License v3.0",
        signals=(
            sig(r"gnu lesser general public license[\s\S]{0,40}?version 3", W_TITLE,
                REGION_HEAD),
            sig(r"gnu lesser general public license as published by the free software "
                r"foundation,\s*either version 3", W_STRONG),
            sig(r"gnu lesser general public license", W_MEDIUM),
        ),
        commercial=COMMERCIAL_CONDITIONAL,
        copyleft=COPYLEFT_FILE,
        obligations=(
            "Dynamic linking usually keeps your application proprietary.",
            "Static linking or inlining pulls the LGPL terms onto your work.",
            "Users must be able to relink against a modified library.",
        ),
    ),
    Profile(
        spdx_id="LGPL-2.1",
        name="GNU Lesser General Public License v2.1",
        signals=(
            sig(r"gnu lesser general public license[\s\S]{0,40}?version 2\.1", W_TITLE,
                REGION_HEAD),
            sig(r"gnu lesser general public license as published by the free software "
                r"foundation,\s*either version 2\.1", W_STRONG),
            sig(r"gnu library general public license", W_STRONG),
            sig(r"gnu lesser general public license", W_MEDIUM),
            sig(r"modifications to the library", W_WEAK),
        ),
        commercial=COMMERCIAL_CONDITIONAL,
        copyleft=COPYLEFT_FILE,
        obligations=(
            "Dynamic linking usually keeps your application proprietary.",
            "Static linking requires providing object files so users can relink.",
            "Modifications to the library itself must be released.",
        ),
    ),
    Profile(
        spdx_id="GPL-3.0",
        name="GNU General Public License v3.0",
        signals=(
            # Strict adjacency matters: "gnu general public license" is NOT a
            # substring of "gnu affero general public license", so this title
            # signal cannot fire on AGPL text. Conversely AGPL's body mention of
            # GPL sits far past the head and is out of reach.
            sig(r"\bgnu general public license\b[\s\S]{0,40}?version 3", W_TITLE,
                REGION_HEAD),
            sig(r"gnu general public license as published by the free software "
                r"foundation,\s*either version 3", W_STRONG),
            sig(r"installation information", W_MEDIUM),
            sig(r"anti-circumvention", W_MEDIUM),
            sig(r"gnu general public license", W_WEAK),
        ),
        commercial=COMMERCIAL_CONDITIONAL,
        copyleft=COPYLEFT_PROJECT,
        patent_grant=True,
        obligations=(
            "Derivative works distributed to others must be licensed under GPL-3.0.",
            "Must provide complete corresponding source, including build scripts.",
            "SaaS use is NOT triggered - only distribution is (that is AGPL's job).",
            "Anti-tivoization: must supply installation information for user products.",
        ),
    ),
    Profile(
        spdx_id="GPL-2.0",
        name="GNU General Public License v2.0",
        signals=(
            sig(r"\bgnu general public license\b[\s\S]{0,40}?version 2", W_TITLE,
                REGION_HEAD),
            sig(r"gnu general public license as published by the free software "
                r"foundation,\s*either version 2", W_STRONG),
            sig(r"gnu general public license", W_WEAK),
        ),
        commercial=COMMERCIAL_CONDITIONAL,
        copyleft=COPYLEFT_PROJECT,
        obligations=(
            "Distributed derivative works must be GPL-2.0.",
            "No patent grant, no anti-tivoization clause.",
            "Incompatible with GPL-3.0-only code in the same work.",
        ),
    ),
    Profile(
        spdx_id="AGPL-3.0",
        name="GNU Affero General Public License v3.0",
        signals=(
            sig(r"\bgnu affero general public license\b[\s\S]{0,40}?version 3", W_TITLE,
                REGION_HEAD),
            sig(r"gnu affero general public license as published by the free software "
                r"foundation,\s*either version 3", W_STRONG),
            sig(r"remote network interaction", W_STRONG),
            sig(r"your modified version must offer all users interacting with it "
                r"remotely", W_STRONG),
        ),
        commercial=COMMERCIAL_CONDITIONAL,
        copyleft=COPYLEFT_NETWORK,
        patent_grant=True,
        network_clause=True,
        obligations=(
            "Network use counts as distribution: serving users over a network obliges you to offer source.",
            "This is the clause that forces commercial SaaS users to buy a commercial license.",
            "Derivatives must be AGPL-3.0; it cannot be combined with GPL-2.0-only code.",
        ),
    ),
    Profile(
        spdx_id="BSL-1.0",
        name="Boost Software License 1.0",
        signals=(
            sig(r"boost software license\b[\s\S]{0,30}?version 1\.0", W_TITLE, REGION_HEAD),
            sig(r"boost software license\s*-\s*version 1\.0", W_STRONG),
            sig(r"the copyright notices in the software and this entire statement",
                W_MEDIUM),
        ),
        commercial=COMMERCIAL_OK,
        obligations=(
            "Attribution only in source form; no notice needed in compiled binaries.",
        ),
    ),
    Profile(
        spdx_id="Unlicense",
        name="The Unlicense",
        signals=(
            sig(r"this is free and unencumbered software released into the public "
                r"domain", W_TITLE, REGION_HEAD),
            sig(r"anyone is free to copy,\s*modify,\s*publish,\s*use,\s*compile,\s*"
                r"sell,\s*or distribute this software", W_STRONG),
            sig(r"for more information,\s*please refer to\s*<?https?://unlicense\.org",
                W_MEDIUM),
        ),
        commercial=COMMERCIAL_OK,
        obligations=("No obligations. Public domain dedication.",),
    ),
    Profile(
        spdx_id="CC0-1.0",
        name="Creative Commons Zero v1.0 Universal",
        signals=(
            sig(r"\bcc0 1\.0 universal\b", W_TITLE, REGION_HEAD),
            sig(r"creative commons legal code", W_MEDIUM),
            sig(r"has waived all copyright and related or neighboring rights",
                W_STRONG),
            sig(r"no rights reserved", W_MEDIUM),
        ),
        commercial=COMMERCIAL_OK,
        obligations=("No obligations. Public domain waiver with a permissive fallback.",),
    ),
    Profile(
        spdx_id="CC-BY-4.0",
        name="Creative Commons Attribution 4.0 International",
        signals=(
            sig(r"attribution 4\.0 international", W_TITLE, REGION_HEAD),
            sig(r"creative commons attribution 4\.0", W_STRONG),
            sig(r"by\s*4\.0", W_WEAK),
        ),
        commercial=COMMERCIAL_OK,
        obligations=(
            "Commercial use allowed with attribution.",
            "Not designed for software; there is no patent grant and no warranty disclaimer tuned for code.",
        ),
    ),
    Profile(
        spdx_id="CC-BY-SA-4.0",
        name="Creative Commons Attribution-ShareAlike 4.0 International",
        signals=(
            sig(r"attribution-sharealike 4\.0 international", W_TITLE, REGION_HEAD),
            sig(r"creative commons attribution-sharealike 4\.0", W_STRONG),
        ),
        commercial=COMMERCIAL_CONDITIONAL,
        copyleft=COPYLEFT_PROJECT,
        obligations=(
            "Commercial use allowed, but derivatives must be shared under the same license.",
            "ShareAlike is viral in the same way strong copyleft is.",
        ),
    ),
    Profile(
        spdx_id="Sustainable-Use-1.0",
        name="Sustainable Use License (fair-code, e.g. n8n)",
        signals=(
            sig(r"sustainable use license", W_TITLE, REGION_HEAD),
            sig(r"the software may be used for internal business purposes", W_STRONG),
            sig(r"you may not use the software to provide a commercial service",
                W_STRONG),
            sig(r"\bfair-code\b", W_MEDIUM),
        ),
        commercial=COMMERCIAL_CONDITIONAL,
        obligations=(
            "Internal business use is free. Reselling or hosting it as a service is not.",
            "This is not an OSI-approved open source license; read every clause.",
        ),
    ),
)

PROFILE_BY_ID = {p.spdx_id: p for p in PROFILES}


# --------------------------------------------------------------------------
# Modifiers: what turns a permissive-looking file into a commercial trap
# --------------------------------------------------------------------------

#: Each modifier is (regex, label, effect). Effects are applied after the base
#: license is chosen, because CREATIVE COMMONS distributions in particular
#: reuse the same skeleton and differ only by these two-letter codes.
MODIFIERS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"\bnon-?\s?commercial\b", re.I), "NC", "noncommercial"),
    (re.compile(r"\bno-?\s?derivatives?\b|\bnon-?\s?derivative[s]?\b", re.I), "ND",
     "noderivatives"),
    (re.compile(r"\bshare-?\s?alike\b", re.I), "SA", "sharealike"),
)

#: Creative Commons licenses share one skeleton. Rather than hunting for a
#: distinct fingerprint per NC/ND/SA combination, detect the family and derive
#: the exact id from the modifiers. This is why CC BY-NC-ND 4.0 does not need
#: its own entry.
_CC_FAMILY = re.compile(r"creative\s+commons|creativecommons\.org", re.I)
_CC_VERSION = re.compile(r"\b([1-4])\.0\b")
_CC_EXPLICIT = re.compile(
    r"attribution(?:-non-?commercial)?(?:-no-?derivatives?)?(?:-share-?alike)?"
    r"\s*([1-4]\.0)?\s*international",
    re.I,
)
_CC_PUBLIC_DOMAIN = re.compile(r"cc0|public domain dedication", re.I)

_CUSTOM_SIGNALS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"research\s*(?:&|and)\s*non-?commercial|non-?commercial purpose|"
            r"research\s+purposes?\s+only|for\s+research\s+use\s+only|"
            r"academic\s+and\s+non-?commercial",
            re.I,
        ),
        "自定义：研究/非商业许可",
    ),
    (re.compile(r"all rights reserved", re.I), "版权保留（All rights reserved）"),
)


@dataclass
class Candidate:
    spdx_id: str
    name: str
    score: int
    hits: list[str] = field(default_factory=list)
    #: Scores from signals no other profile shares. This is what actually
    #: separates sibling variants (BSD-2 vs BSD-3, GPL-2 vs GPL-3), because the
    #: shared clauses contribute equally to both and carry no information.
    distinctive: int = 0

    def to_dict(self) -> dict:
        return {"spdx_id": self.spdx_id, "name": self.name, "score": self.score,
                "distinctive": self.distinctive, "hits": self.hits}


@dataclass
class Verdict:
    """The judge's answer, including its doubt."""

    spdx_id: str
    name: str
    confidence: float
    decisive: bool
    candidates: list[Candidate]
    commercial: str = COMMERCIAL_UNKNOWN
    copyleft: str = COPYLEFT_NONE
    obligations: tuple[str, ...] = ()
    patent_grant: bool = False
    network_clause: bool = False
    modifiers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    profile: Profile | None = None

    def to_dict(self) -> dict:
        return {
            "spdx_id": self.spdx_id,
            "name": self.name,
            "confidence": round(self.confidence, 3),
            "decisive": self.decisive,
            "commercial": self.commercial,
            "copyleft": self.copyleft,
            "obligations": list(self.obligations),
            "patent_grant": self.patent_grant,
            "network_clause": self.network_clause,
            "modifiers": list(self.modifiers),
            "warnings": list(self.warnings),
            "candidates": [c.to_dict() for c in self.candidates],
        }


#: Below this total score, we refuse to name a license.
MIN_DECISIVE_SCORE = 55
#: If the runner-up is within this margin, the answer is ambiguous.
MIN_MARGIN = 18


def _score_profile(profile: Profile, head: str, body: str,
                   shared_patterns: set[str] | None = None) -> Candidate:
    total = 0
    distinctive = 0
    hits: list[str] = []
    for signal in profile.signals:
        haystack = head if signal.region == REGION_HEAD else body
        match = signal.pattern.search(haystack)
        if match:
            total += signal.weight
            if shared_patterns is None or signal.pattern.pattern not in shared_patterns:
                distinctive += signal.weight
            hits.append(f"{signal.region}:{match.group(0)[:48]!r}(+{signal.weight})")
    return Candidate(profile.spdx_id, profile.name, total, hits, distinctive)


def _shared_patterns() -> set[str]:
    """Signal patterns used by more than one profile.

    These carry no discriminative information between the profiles that share
    them, so they are excluded from the ``distinctive`` tally used to break
    near-ties. Without this, BSD-2 and BSD-3 remain indistinguishable: both
    score the two shared clauses, and the comparison collapses to noise.
    """
    seen: dict[str, int] = {}
    for profile in PROFILES:
        for signal in profile.signals:
            seen[signal.pattern.pattern] = seen.get(signal.pattern.pattern, 0) + 1
    return {pattern for pattern, count in seen.items() if count > 1}


def _apply_modifiers(
    profile: Profile, body: str, verdict: Verdict
) -> None:
    """Downgrade the verdict when NC/ND/SA riders are present."""
    detected = [label for pattern, label, _ in MODIFIERS if pattern.search(body)]
    verdict.modifiers = detected

    is_cc = profile.spdx_id.startswith("CC-")
    if "NC" in detected and profile.commercial != COMMERCIAL_FORBIDDEN:
        verdict.commercial = COMMERCIAL_FORBIDDEN
        verdict.warnings.append(
            "NC clause detected: commercial use is forbidden without a separate commercial license."
        )
    if "ND" in detected:
        verdict.warnings.append(
            "ND clause detected: modified redistribution is forbidden - this blocks most software reuse."
        )
    if "SA" in detected and profile.copyleft == COPYLEFT_NONE and not is_cc:
        verdict.copyleft = COPYLEFT_PROJECT
        verdict.warnings.append(
            "ShareAlike detected: derivative works must carry the same license."
        )


def judge_creative_commons(normalized: str, head: str) -> Verdict | None:
    """Resolve a Creative Commons license from its family + modifier code.

    CC licenses are the dominant license for datasets, model weights, articles
    and artwork, and they are exactly where a naive judge fails: the NC variant
    looks permissive until you read two words. Deriving the id from the
    modifier set covers all 4.0 combinations without a fingerprint each.
    """
    if not _CC_FAMILY.search(head) and not _CC_FAMILY.search(normalized):
        return None
    if _CC_PUBLIC_DOMAIN.search(head):
        return None  # CC0 has its own profile and is handled upstream.

    if not re.search(r"attribution", head, re.I):
        # A CC notice that never names Attribution is probably a reference to
        # another work's license, not this file's license.
        return None

    modifiers = [label for pattern, label, _ in MODIFIERS if pattern.search(head)]
    version = "4.0"
    match = _CC_VERSION.search(head)
    if match:
        version = f"{match.group(1)}.0"

    code = "CC-BY"
    parts = ["BY"]
    if "NC" in modifiers:
        parts.append("NC")
    if "SA" in modifiers:
        parts.append("SA")
    if "ND" in modifiers:
        parts.append("ND")
    code = "CC-" + "-".join(parts) + f"-{version}"

    commercial = COMMERCIAL_FORBIDDEN if "NC" in modifiers else COMMERCIAL_OK
    copyleft = COPYLEFT_PROJECT if "SA" in modifiers else COPYLEFT_NONE

    obligations: list[str] = ["Must credit the creator, link the license, and indicate changes."]
    warnings: list[str] = []
    if "NC" in modifiers:
        obligations.append("NonCommercial: no use primarily aimed at commercial advantage or payment.")
        warnings.append(
            "NC forbids commercial use. For a dataset or model this blocks shipping it "
            "inside a paid product without a separate license from the author."
        )
    if "ND" in modifiers:
        obligations.append("NoDerivatives: modified versions may not be distributed.")
        warnings.append(
            "ND forbids distributing modified copies - for model weights this even "
            "casts doubt on fine-tuning and redistribution."
        )
    if "SA" in modifiers:
        obligations.append("ShareAlike: adaptations must carry the same CC license.")
    if version in ("1.0", "2.0", "3.0"):
        warnings.append(
            f"Version {version} predates the 4.0 rewrite; attribution mechanics differ "
            "and 3.0 has no automatic curing of license violations."
        )

    verdict = Verdict(
        spdx_id=code,
        name=f"Creative Commons {code.removeprefix('CC-')}",
        confidence=0.92,
        decisive=True,
        candidates=[Candidate(code, code, 200)],
        commercial=commercial,
        copyleft=copyleft,
        obligations=tuple(obligations),
        modifiers=modifiers,
        warnings=warnings,
    )
    if "NC" not in modifiers and "ND" not in modifiers:
        verdict.warnings.append(
            "Creative Commons licenses are written for creative works, not software: "
            "no patent grant, and no warranty disclaimer tuned for code."
        )
    return verdict


def judge(text: str, *, head_chars: int = HEAD_CHARS) -> Verdict:
    """Classify a license document.

    The function is pure: same input, same output, no I/O.
    """
    normalized = normalize(text)

    if not normalized:
        return Verdict(
            spdx_id="NONE",
            name="No license text",
            confidence=1.0,
            decisive=False,
            candidates=[],
            commercial=COMMERCIAL_UNKNOWN,
            warnings=[
                "No license text found. Default copyright applies: all rights reserved, "
                "so commercial use is NOT permitted."
            ],
            obligations=("Read/reference only. Copying code into your product requires permission.",),
        )

    head = head_of(normalized, head_chars)

    # Creative Commons resolution runs before the generic scorer can settle on a
    # near-miss (an NC file used to land on "unrecognized" because the CC-BY
    # fingerprint requires wording the NC variant does not contain), and before
    # the "does this look legal" gate, because a short CC notice such as
    # "Attribution-NonCommercial 4.0 International" is a complete license label
    # even though it contains none of the generic legal markers.
    cc = judge_creative_commons(normalized, head)
    if cc is not None:
        return cc

    if not looks_like_license_text(normalized):
        return Verdict(
            spdx_id="UNRECOGNIZED",
            name="Not recognizable as legal text",
            confidence=0.2,
            decisive=False,
            candidates=[],
            commercial=COMMERCIAL_UNKNOWN,
            warnings=["The file is too short or contains no legal markers; treat as unlicensed until a human reads it."],
        )

    shared = _shared_patterns()
    scored = [_score_profile(p, head, normalized, shared) for p in PROFILES]
    # Rank by total score, then by distinctive evidence. The second key resolves
    # sibling variants whose shared clauses dominate the total.
    scored.sort(key=lambda c: (c.score, c.distinctive), reverse=True)
    top = scored[0] if scored else Candidate("UNRECOGNIZED", "unknown", 0)
    runner_up = scored[1] if len(scored) > 1 else Candidate("UNRECOGNIZED", "unknown", 0)

    body_without_head = normalized[len(head):]
    custom: list[str] = []
    for pattern, label in _CUSTOM_SIGNALS:
        if pattern.search(normalized):
            custom.append(label)

    if top.score < MIN_DECISIVE_SCORE:
        # Nothing scored well. Custom or non-commercial riders are the most
        # likely reason, and they change the answer commercially.
        custom_label = custom[0] if custom else "其它/需人工细读"
        verdict = Verdict(
            spdx_id="CUSTOM" if custom else "UNRECOGNIZED",
            name=custom_label,
            confidence=min(1.0, top.score / max(MIN_DECISIVE_SCORE, 1)),
            decisive=False,
            candidates=scored[:4],
            commercial=COMMERCIAL_FORBIDDEN if custom else COMMERCIAL_UNKNOWN,
            warnings=["No standard fingerprint scored high enough. A human must read this license."],
        )
        if custom:
            verdict.warnings.append(
                f"Custom rider detected ({custom_label}); it overrides any permissive-sounding wording."
            )
        return verdict

    margin = top.score - runner_up.score
    decisive = margin >= MIN_MARGIN
    # Confidence is driven by *margin*, not by the ratio of scores. A runner-up
    # that scores well purely from body cross-references (MPL-2.0 citing the
    # GNU family, EPL-2.0 quoting GPL) should not make a correct verdict look
    # shaky; what matters is how far ahead the winner is.
    if decisive:
        confidence = min(1.0, 0.60 + margin / 500.0)
    else:
        confidence = min(0.5, 0.5 * (margin / MIN_MARGIN))

    profile = PROFILE_BY_ID[top.spdx_id]
    verdict = Verdict(
        spdx_id=profile.spdx_id,
        name=profile.name,
        confidence=confidence,
        decisive=decisive,
        candidates=scored[:4],
        commercial=profile.commercial,
        copyleft=profile.copyleft,
        obligations=profile.obligations,
        patent_grant=profile.patent_grant,
        network_clause=profile.network_clause,
        profile=profile,
    )

    if not decisive:
        verdict.warnings.append(
            f"Ambiguous: {top.spdx_id} ({top.score}) leads {runner_up.spdx_id} "
            f"({runner_up.score}) by only {margin}. Read the file before relying on this."
        )

    _apply_modifiers(profile, normalized, verdict)

    # A body-only "all rights reserved" line is a copyright notice, not a
    # license term. It must never override a recognized license -- this is the
    # classic BSD/MIT mislabel.
    if "版权保留（All rights reserved）" in custom and not verdict.modifiers:
        verdict.warnings.append(
            "Contains an 'All rights reserved' notice. That is a copyright statement, "
            "not a license term; the license above still governs."
        )

    return verdict


# --------------------------------------------------------------------------
# SPDX expression support (package.json, Cargo.toml, composer.json ...)
# --------------------------------------------------------------------------

_SPDX_TOKEN = re.compile(r"[A-Za-z0-9.+\-]+")


def judge_expression(expression: str) -> Verdict:
    """Evaluate an SPDX license *expression* such as ``MIT OR Apache-2.0``.

    Dual licensing is almost always good news commercially: you pick whichever
    side suits you. ``AND`` is the dangerous one - both sets of obligations
    stack, so the composite inherits the harshest term.
    """
    raw = (expression or "").strip()
    if not raw:
        return judge("")

    # A concrete license id is not an expression. "GPL-3.0-or-later" contains OR
    # as a substring, so it must be resolved as an id before any operator
    # parsing happens - otherwise every "-or-later" license is misreported as a
    # dual license (which would wildly understate the obligation).
    direct = _lookup(raw)
    if direct is not None:
        verdict = _verdict_for_profile(direct)
        verdict.spdx_id = _canonical_token(raw, direct)
        return verdict

    upper = raw.upper()
    # Only treat AND/OR as operators when they stand alone as words.
    tokens = [t for t in _SPDX_TOKEN.findall(raw)]
    ids = [t for t in tokens if t.upper() not in {"AND", "OR", "WITH", "AND/OR"}]

    known: list[Profile] = []
    unknown: list[str] = []
    for token in ids:
        profile = _lookup(token)
        if profile:
            known.append(profile)
        else:
            unknown.append(token)

    if not known:
        verdict = judge("")
        verdict.spdx_id = "UNRECOGNIZED"
        verdict.name = f"Unrecognized expression: {raw}"
        verdict.warnings = [f"No token in {raw!r} matches a known license id."]
        return verdict

    has_or = re.search(r"\bOR\b", upper) is not None
    has_and = re.search(r"\bAND\b", upper) is not None

    if has_or and not has_and:
        best = min(known, key=_commercial_rank)
        verdict = Verdict(
            spdx_id=raw,
            name=f"Dual license, choose one: {raw}",
            confidence=1.0,
            decisive=True,
            candidates=[Candidate(p.spdx_id, p.name, 100) for p in known],
            commercial=best.commercial,
            copyleft=best.copyleft,
            obligations=best.obligations + (
                f"Pick the {best.spdx_id} branch and comply with it only.",),
            patent_grant=best.patent_grant,
            network_clause=best.network_clause,
            profile=best,
        )
        verdict.warnings.append(
            "OR means you may comply with any one branch; the permissive branch is the cheapest path."
        )
        return verdict

    worst = max(known, key=_commercial_rank)
    verdict = Verdict(
        spdx_id=raw,
        name=f"Combined license, all apply: {raw}",
        confidence=1.0,
        decisive=True,
        candidates=[Candidate(p.spdx_id, p.name, 100) for p in known],
        commercial=worst.commercial,
        copyleft=worst.copyleft,
        obligations=tuple(o for p in known for o in p.obligations),
        patent_grant=all(p.patent_grant for p in known),
        network_clause=any(p.network_clause for p in known),
        profile=worst,
    )
    verdict.warnings.append(
        "AND means every branch applies at once, so the strictest obligation wins."
    )
    if unknown:
        verdict.warnings.append(f"Unrecognized ids in expression: {', '.join(unknown)}")
    return verdict


def _canonical_token(raw: str, profile: Profile) -> str:
    """Present a single-id expression in its SPDX-canonical form.

    ``gpl-3.0-or-later`` and ``GPL-3.0-or-later`` both normalise to
    ``GPL-3.0-or-later``; the suffix is meaningful to a lawyer (it decides
    whether the project may relicense under a future version), so it is kept.
    """
    lowered = raw.strip().lower()
    if lowered.endswith("-or-later"):
        return f"{profile.spdx_id}-or-later"
    if lowered.endswith("-only"):
        return f"{profile.spdx_id}-only"
    return profile.spdx_id


def _verdict_for_profile(profile: Profile) -> Verdict:
    """Build a verdict directly from a known profile (no text to score)."""
    return Verdict(
        spdx_id=profile.spdx_id,
        name=profile.name,
        confidence=1.0,
        decisive=True,
        candidates=[Candidate(profile.spdx_id, profile.name, 100, ["spdx-id"])],
        commercial=profile.commercial,
        copyleft=profile.copyleft,
        obligations=profile.obligations,
        patent_grant=profile.patent_grant,
        network_clause=profile.network_clause,
        profile=profile,
    )


def _commercial_rank(profile: Profile) -> int:
    order = {
        COMMERCIAL_OK: 0,
        COMMERCIAL_CONDITIONAL: 1,
        COMMERCIAL_UNKNOWN: 2,
        COMMERCIAL_FORBIDDEN: 3,
    }
    copyleft_order = {
        COPYLEFT_NONE: 0,
        COPYLEFT_FILE: 1,
        COPYLEFT_PROJECT: 2,
        COPYLEFT_NETWORK: 3,
    }
    return order.get(profile.commercial, 2) * 10 + copyleft_order.get(profile.copyleft, 0)


_ALIASES: dict[str, str] = {
    "mit": "MIT",
    "isc": "ISC",
    "bsd-2-clause": "BSD-2-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "apache-2.0": "Apache-2.0",
    "apache2": "Apache-2.0",
    "mpl-2.0": "MPL-2.0",
    "epl-2.0": "EPL-2.0",
    "lgpl-3.0": "LGPL-3.0",
    "lgpl-3.0-only": "LGPL-3.0",
    "lgpl-3.0-or-later": "LGPL-3.0",
    "lgpl-2.1": "LGPL-2.1",
    "lgpl-2.1-only": "LGPL-2.1",
    "lgpl-2.1-or-later": "LGPL-2.1",
    "gpl-3.0": "GPL-3.0",
    "gpl-3.0-only": "GPL-3.0",
    "gpl-3.0-or-later": "GPL-3.0",
    "gpl-2.0": "GPL-2.0",
    "gpl-2.0-only": "GPL-2.0",
    "gpl-2.0-or-later": "GPL-2.0",
    "agpl-3.0": "AGPL-3.0",
    "agpl-3.0-only": "AGPL-3.0",
    "agpl-3.0-or-later": "AGPL-3.0",
    "bsl-1.0": "BSL-1.0",
    "unlicense": "Unlicense",
    "cc0-1.0": "CC0-1.0",
    "cc-by-4.0": "CC-BY-4.0",
    "cc-by-sa-4.0": "CC-BY-SA-4.0",
}


def _lookup(token: str) -> Profile | None:
    key = token.strip().lower()
    if key in _ALIASES:
        return PROFILE_BY_ID.get(_ALIASES[key])
    for spdx_id, profile in PROFILE_BY_ID.items():
        if spdx_id.lower() == key:
            return profile
    return None


def explain(verdict: Verdict) -> str:
    """Human-readable, one screen, ordered by what the reader must act on."""
    lines = [
        f"{verdict.name}  [{verdict.spdx_id}]",
        f"  confidence   {verdict.confidence:.0%}"
        f"{'' if verdict.decisive else '  (NOT decisive)'}",
        f"  commercial   {verdict.commercial}",
        f"  copyleft     {verdict.copyleft}"
        + ("  (network clause)" if verdict.network_clause else ""),
    ]
    if verdict.modifiers:
        lines.append(f"  modifiers    {', '.join(verdict.modifiers)}")
    if verdict.obligations:
        lines.append("  obligations")
        lines.extend(f"    - {o}" for o in verdict.obligations)
    if verdict.candidates:
        lines.append("  evidence")
        for candidate in verdict.candidates[:3]:
            lines.append(f"    {candidate.spdx_id:<16} {candidate.score:>4}")
    if verdict.warnings:
        lines.append("  warnings")
        lines.extend(f"    ! {w}" for w in verdict.warnings)
    return "\n".join(lines)


def judge_files(paths: Iterable) -> list[Verdict]:
    results: list[Verdict] = []
    for path in paths:
        with open(path, encoding="utf-8", errors="replace") as handle:
            results.append(judge(handle.read()))
    return results