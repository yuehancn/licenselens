"""Regression tests for the judge and the policy engine.

Every assertion here maps to a real misclassification. If one fails, a user with
a copyleft dependency may be told they are clear to ship - which is the
expensive kind of bug, so these run in CI on every push.

The suite is dependency-free on purpose: ``python tests/test_all.py`` works on a
machine where ``pip install pytest`` is not possible.
"""

from __future__ import annotations

import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))
sys.path.insert(0, str(HERE))

from _runner import case, main, parametrize  # noqa: E402

from licenselens.judge import (  # noqa: E402
    COMMERCIAL_CONDITIONAL,
    COMMERCIAL_FORBIDDEN,
    COMMERCIAL_OK,
    COMMERCIAL_UNKNOWN,
    COPYLEFT_NETWORK,
    COPYLEFT_PROJECT,
    PROFILE_BY_ID,
    judge,
    judge_expression,
    REGION_HEAD,
)
from licenselens.policy import Decision, Policy, evaluate  # noqa: E402

FIXTURES = HERE / "fixtures"

#: Canonical license bodies fetched from the GitHub Licenses API and committed
#: verbatim, so the suite never needs the network.
CANONICAL = {
    "mit.txt": "MIT",
    "isc.txt": "ISC",
    "bsd-2-clause.txt": "BSD-2-Clause",
    "bsd-3-clause.txt": "BSD-3-Clause",
    "apache-2.0.txt": "Apache-2.0",
    "mpl-2.0.txt": "MPL-2.0",
    "epl-2.0.txt": "EPL-2.0",
    "lgpl-2.1.txt": "LGPL-2.1",
    "lgpl-3.0.txt": "LGPL-3.0",
    "gpl-2.0.txt": "GPL-2.0",
    "gpl-3.0.txt": "GPL-3.0",
    "agpl-3.0.txt": "AGPL-3.0",
    "bsl-1.0.txt": "BSL-1.0",
    "unlicense.txt": "Unlicense",
    "cc0-1.0.txt": "CC0-1.0",
}


def load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8", errors="replace")


@parametrize(sorted(CANONICAL.items()))
def test_canonical_texts_are_identified(filename: str, expected: str) -> None:
    verdict = judge(load(filename))
    assert verdict.spdx_id == expected, (
        f"{filename} -> {verdict.spdx_id}, expected {expected}; "
        f"candidates={[(c.spdx_id, c.score) for c in verdict.candidates]}"
    )
    assert verdict.decisive, f"{filename} produced a non-decisive verdict"


@parametrize(sorted(CANONICAL.items()))
def test_canonical_texts_are_confident(filename: str, expected: str) -> None:
    verdict = judge(load(filename))
    assert verdict.confidence >= 0.6, f"{filename} confidence {verdict.confidence}"


# ---------------------------------------------------------------------------
# Cross-reference traps: a whole-document grep gets both of these wrong.
# ---------------------------------------------------------------------------


@case
def test_gpl3_body_mentions_affero_but_verdict_is_gpl3() -> None:
    """GPL-3.0 section 13 is titled "Use with the GNU Affero General Public License".

    A judge that greps the whole document for "Affero" returns AGPL-3.0 and tells
    the user a network-copyleft obligation applies when it does not.
    """
    body = load("gpl-3.0.txt")
    assert "affero general public license" in body.lower(), (
        "fixture no longer contains the Affero cross-reference; test is stale"
    )
    verdict = judge(body)
    assert verdict.spdx_id == "GPL-3.0"
    assert verdict.copyleft == COPYLEFT_PROJECT
    assert not verdict.network_clause


@case
def test_lgpl21_quotes_gpl_but_stays_lesser() -> None:
    body = load("lgpl-2.1.txt")
    verdict = judge(body)
    assert verdict.spdx_id == "LGPL-2.1"
    assert verdict.copyleft != COPYLEFT_PROJECT


@case
def test_apache_body_mentions_gpl_but_stays_apache() -> None:
    verdict = judge(load("apache-2.0.txt"))
    assert verdict.spdx_id == "Apache-2.0"
    assert verdict.patent_grant is True


@case
def test_mit_with_all_rights_reserved_is_still_mit() -> None:
    body = load("mit.txt") + "\nAll rights reserved.\n"
    verdict = judge(body)
    assert verdict.spdx_id == "MIT"
    assert verdict.commercial == COMMERCIAL_OK


@case
def test_bsd3_with_all_rights_reserved_stays_permissive() -> None:
    body = load("bsd-3-clause.txt").replace(
        "Copyright (c) [year], [fullname]",
        "Copyright (c) 2026, Someone. All rights reserved.",
    )
    verdict = judge(body)
    assert verdict.spdx_id == "BSD-3-Clause"
    assert verdict.commercial == COMMERCIAL_OK


# ---------------------------------------------------------------------------
# Creative Commons
# ---------------------------------------------------------------------------


@case
def test_bsd3_from_pallets_flask_resolves_to_three_clause() -> None:
    """Real-world regression: pallets/flask's LICENSE.txt.

    Flask's license omits the "BSD 3-Clause License" title line and jumps
    straight into the clauses. Clauses 1 and 2 are shared with BSD-2, so scoring
    those at high weight used to make BSD-2 win 145 to 140. Only clause 3
    ("Neither the name of ... nor the names of its contributors may be used to
    endorse") distinguishes them, and the shipped verdict must key on it.
    """
    text = (
        "Copyright 2010 Pallets\n\n"
        "Redistribution and use in source and binary forms, with or without\n"
        "modification, are permitted provided that the following conditions are\n"
        "met:\n\n"
        "1.  Redistributions of source code must retain the above copyright\n"
        "    notice, this list of conditions and the following disclaimer.\n\n"
        "2.  Redistributions in binary form must reproduce the above copyright\n"
        "    notice, this list of conditions and the following disclaimer in the\n"
        "    documentation and/or other materials provided with the distribution.\n\n"
        "3.  Neither the name of the copyright holder nor the names of its\n"
        "    contributors may be used to endorse or promote products derived from\n"
        "    this software without specific prior written permission.\n\n"
        "THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS\n"
        '"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED.\n'
    )
    verdict = judge(text)
    assert verdict.spdx_id == "BSD-3-Clause", verdict.spdx_id
    top, second = verdict.candidates[0], verdict.candidates[1]
    assert top.distinctive > second.distinctive


@case
def test_shared_clauses_carry_no_discriminative_weight() -> None:
    """BSD-2/BSD-3 resolve on clause 3, not on the clauses they share."""
    two_clause = (
        "Copyright (c) 2026 Someone\n\n"
        "Redistribution and use in source and binary forms, with or without\n"
        "modification, are permitted provided that the following conditions are met:\n\n"
        "1. Redistributions of source code must retain the above copyright notice.\n\n"
        "2. Redistributions in binary form must reproduce the above copyright notice.\n"
    )
    verdict = judge(two_clause)
    assert verdict.spdx_id == "BSD-2-Clause", verdict.spdx_id


@case
def test_cc_by_nc_is_forbidden_commercially() -> None:
    text = (
        "Creative Commons Attribution-NonCommercial 4.0 International Public License\n"
        "By exercising the Licensed Rights, You accept and agree to be bound by the terms "
        "and conditions of this Creative Commons Attribution-NonCommercial 4.0 "
        "International Public License. NonCommercial means not primarily intended for or "
        "directed towards commercial advantage."
    )
    verdict = judge(text)
    assert verdict.spdx_id == "CC-BY-NC-4.0", verdict.spdx_id
    assert verdict.commercial == COMMERCIAL_FORBIDDEN
    assert "NC" in verdict.modifiers


@case
def test_cc_by_nc_sa_derives_both_modifiers() -> None:
    text = (
        "Attribution-NonCommercial-ShareAlike 4.0 International\n"
        "Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International Public "
        "License. ShareAlike means adaptations must carry the same terms. "
        "NonCommercial means not primarily intended for commercial advantage."
    )
    verdict = judge(text)
    assert verdict.spdx_id == "CC-BY-NC-SA-4.0", verdict.spdx_id
    assert verdict.commercial == COMMERCIAL_FORBIDDEN
    assert set(verdict.modifiers) >= {"NC", "SA"}
    assert verdict.copyleft == COPYLEFT_PROJECT


@case
def test_cc_by_40_is_commercially_allowed() -> None:
    text = (
        "Attribution 4.0 International (CC BY 4.0)\n"
        "Creative Commons Attribution 4.0 International Public License. You are free to "
        "share and adapt the material for any purpose, even commercially."
    )
    verdict = judge(text)
    assert verdict.spdx_id == "CC-BY-4.0", verdict.spdx_id
    assert verdict.commercial == COMMERCIAL_OK


@case
def test_cc0_is_not_treated_as_attribution() -> None:
    verdict = judge(load("cc0-1.0.txt"))
    assert verdict.spdx_id == "CC0-1.0"
    assert verdict.commercial == COMMERCIAL_OK


# ---------------------------------------------------------------------------
# Custom riders
# ---------------------------------------------------------------------------


@case
def test_research_only_license_is_not_permissive() -> None:
    text = (
        "Model Research License\n"
        "This model is made available for research and non-commercial uses only. "
        "Any commercial use requires a separate written license from the authors. "
        "Permission is hereby granted, free of charge, to any person obtaining a copy "
        "of this software for academic research."
    )
    verdict = judge(text)
    assert verdict.commercial in (COMMERCIAL_FORBIDDEN, COMMERCIAL_UNKNOWN)


@case
def test_sustainable_use_license_flags_resale_restriction() -> None:
    text = (
        "Sustainable Use License\n"
        "The software may be used for internal business purposes free of charge. "
        "You may not use the software to provide a commercial service to third parties "
        "without a separate agreement. This is a fair-code distribution."
    )
    verdict = judge(text)
    assert verdict.spdx_id == "Sustainable-Use-1.0"
    assert verdict.commercial == COMMERCIAL_CONDITIONAL


# ---------------------------------------------------------------------------
# Degenerate inputs must not read as permissive
# ---------------------------------------------------------------------------


@case
def test_empty_text_is_unlicensed_not_permissive() -> None:
    verdict = judge("")
    assert verdict.spdx_id == "NONE"
    assert verdict.commercial == COMMERCIAL_UNKNOWN
    assert any("all rights reserved" in w.lower() for w in verdict.warnings)


@case
def test_short_noise_is_not_guessed() -> None:
    verdict = judge("MIT")
    assert verdict.spdx_id == "UNRECOGNIZED"
    assert not verdict.decisive


@case
def test_html_escaped_payload_is_unescaped() -> None:
    escaped = (
        "&lt;p&gt;MIT License&lt;/p&gt;&lt;p&gt;Copyright (c) 2026 Someone&lt;/p&gt;"
        "&lt;p&gt;Permission is hereby granted, free of charge, to any person obtaining "
        "a copy of this software and associated documentation files (the "
        "&quot;Software&quot;), to deal in the Software without restriction.&lt;/p&gt;"
    )
    verdict = judge(escaped)
    assert verdict.spdx_id == "MIT", verdict.spdx_id


@case
def test_proprietary_notice_returns_visible_doubt() -> None:
    text = (
        "Proprietary Notice\n"
        "This source code is confidential and licensed only to the named licensee under "
        "the terms of a separate signed agreement. Redistribution is prohibited. "
        "All rights reserved by the copyright holder."
    )
    verdict = judge(text)
    assert not verdict.decisive


# ---------------------------------------------------------------------------
# SPDX expressions
# ---------------------------------------------------------------------------


@case
def test_or_expression_picks_the_cheapest_branch() -> None:
    verdict = judge_expression("MIT OR GPL-3.0")
    assert verdict.commercial == COMMERCIAL_OK


@case
def test_and_expression_inherits_the_strictest_term() -> None:
    verdict = judge_expression("MIT AND AGPL-3.0")
    assert verdict.commercial == COMMERCIAL_CONDITIONAL
    assert verdict.network_clause is True


@case
def test_dual_permissive_expression_stays_permissive() -> None:
    assert judge_expression("Apache-2.0 OR MIT").commercial == COMMERCIAL_OK


@case
def test_expression_suffixes_are_normalized_not_mistaken_for_dual_license() -> None:
    """"-or-later" contains the substring "or" but is a single license id.

    Treating it as ``A OR B`` would badly understate the obligation, so the
    suffix must be resolved as part of the id and then preserved (it decides
    whether the project may relicense under a future version).
    """
    verdict = judge_expression("GPL-3.0-or-later")
    assert verdict.spdx_id == "GPL-3.0-or-later", verdict.spdx_id
    assert verdict.copyleft == COPYLEFT_PROJECT
    assert judge_expression("LGPL-2.1-only").spdx_id == "LGPL-2.1-only"
    assert judge_expression("gpl-3.0-or-later").spdx_id == "GPL-3.0-or-later"


@case
def test_unknown_expression_is_flagged_not_guessed() -> None:
    verdict = judge_expression("SEE LICENSE IN README.md")
    assert verdict.spdx_id == "UNRECOGNIZED"
    assert verdict.decisive is False


# ---------------------------------------------------------------------------
# Structural properties the design claims
# ---------------------------------------------------------------------------


@case
def test_verdicts_are_order_independent() -> None:
    """Verdicts must not depend on the order of PROFILES.

    A hand-written if/elif chain fails this by construction. Scoring is additive
    and region-aware, so permuting the profile list must not move any verdict.
    """
    baseline = {name: judge(load(name)).spdx_id for name in CANONICAL}

    # ``import licenselens.judge as module`` binds the *function* re-exported by
    # the package __init__, not the submodule, so the attribute lookup below
    # would fail. Import the module through sys.modules instead.
    import sys as _sys

    module = _sys.modules["licenselens.judge"]

    original = module.PROFILES
    try:
        module.PROFILES = tuple(reversed(original))
        reordered = {name: judge(load(name)).spdx_id for name in CANONICAL}
    finally:
        module.PROFILES = original

    assert baseline == reordered


@case
def test_every_profile_has_a_title_signal() -> None:
    """A profile with no head-region signal can be hijacked by body mentions."""
    for spdx_id, profile in PROFILE_BY_ID.items():
        assert any(s.region == REGION_HEAD for s in profile.signals), spdx_id


@case
def test_network_clause_only_on_agpl() -> None:
    flagged = {p.spdx_id for p in PROFILE_BY_ID.values() if p.network_clause}
    assert flagged == {"AGPL-3.0"}, flagged


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


@case
def test_no_license_blocks_shipping() -> None:
    decision, findings = evaluate(judge(""), Policy())
    assert decision == Decision.BLOCK
    assert any(f.code == "NO-LICENSE" for f in findings)


@case
def test_mit_is_shippable() -> None:
    decision, _ = evaluate(judge(load("mit.txt")), Policy())
    assert decision == Decision.ALLOW


@case
def test_agpl_blocks_closed_source_distribution() -> None:
    decision, findings = evaluate(judge(load("agpl-3.0.txt")), Policy())
    assert decision == Decision.BLOCK
    assert any(f.code == "NETWORK-COPYLEFT" for f in findings)


@case
def test_gpl_blocks_closed_source_but_not_saas() -> None:
    gpl = judge(load("gpl-3.0.txt"))
    blocked, _ = evaluate(gpl, Policy())
    assert blocked == Decision.BLOCK
    allowed, _ = evaluate(gpl, Policy.saas())
    assert allowed != Decision.BLOCK


@case
def test_agpl_blocks_even_saas() -> None:
    decision, _ = evaluate(judge(load("agpl-3.0.txt")), Policy.saas())
    assert decision == Decision.BLOCK


@case
def test_weak_copyleft_respects_policy_toggle() -> None:
    mpl = judge(load("mpl-2.0.txt"))
    assert evaluate(mpl, Policy())[0] == Decision.ALLOW
    strict, _ = evaluate(mpl, Policy.permissive_only())
    assert strict != Decision.ALLOW


@case
def test_staleness_is_reported_as_review() -> None:
    decision, findings = evaluate(judge(load("mit.txt")), Policy(), staleness_days=900)
    assert decision == Decision.REVIEW
    assert any(f.code == "STALE" for f in findings)


@case
def test_archived_is_reported() -> None:
    _, findings = evaluate(judge(load("mit.txt")), Policy(), archived=True)
    assert any(f.code == "ARCHIVED" for f in findings)


@case
def test_nc_blocks_commercial_use_via_policy() -> None:
    text = (
        "Creative Commons Attribution-NonCommercial 4.0 International\n"
        "NonCommercial means not primarily intended for commercial advantage."
    )
    decision, findings = evaluate(judge(text), Policy())
    assert decision == Decision.BLOCK
    assert any(f.code == "NONCOMMERCIAL" for f in findings)


@case
def test_manifest_scan_reads_nested_manifests() -> None:
    """Both manifest formats are read, and nested projects are not skipped."""
    from licenselens.manifest import scan_manifests

    root = HERE.parent / "examples" / "demo"
    entries = scan_manifests(root, Policy())
    by_name = {e.name: e for e in entries}
    assert "react" in by_name
    assert "requests" in by_name
    # The project's own license is read from package.json / pyproject.toml.
    assert by_name["demo-app"].license_declared == "MIT"
    assert by_name["demo-service"].license_declared == "AGPL-3.0"
    assert by_name["demo-service"].decision == Decision.BLOCK


@case
def test_manifest_does_not_guess_undeclared_dependency_licenses() -> None:
    """An undeclared dependency must stay 'review', never be assumed permissive."""
    from licenselens.manifest import scan_manifests

    entries = scan_manifests(HERE.parent / "examples" / "demo", Policy())
    react = next(e for e in entries if e.name == "react")
    assert react.license_declared == ""
    assert react.verdict is None
    assert react.decision == Decision.REVIEW


@case
def test_registry_version_ranges_are_concretised() -> None:
    from licenselens.registry import clean_version

    assert clean_version("^18.2.0") == "18.2.0"
    assert clean_version("~=4.2") == "4.2"
    assert clean_version("==1.0.0") == "1.0.0"
    # Open ranges have no single version; ask the registry for latest instead.
    assert clean_version(">=1.0,<2.0") == ""
    assert clean_version("*") == ""


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))