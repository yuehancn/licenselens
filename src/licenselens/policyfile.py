"""Load a policy from a file, so "what we accept" lives in the repo.

The four built-in postures answer "what does a typical company accept". Every
real organisation has one or two deviations: a legal team that has signed off on
one specific AGPL component, a hardware product that may link LGPL statically, a
subsidiary whose GPL obligation was already discharged. Without a file, those
deviations get handled by *ignoring the tool*, which is how a compliance gate
turns into a comment in a code review.

Two design commitments, both aimed at the failure mode this whole project exists
to prevent - a scanner that quietly reports the wrong thing:

**A typo is a hard error.** ``allow_strong_copyeft`` (note the spelling) would,
under a lenient loader, parse cleanly, change nothing, and leave the team
believing they had loosened the rule. Every key is checked against a known set
and an unknown one aborts with its line number. Same for license identifiers: a
misspelled id that silently never matches is worse than no override at all.

**The subset of YAML is deliberate and small.** This project has no runtime
dependencies and will not gain one for a config file, so there is no PyYAML.
Rather than half-implement a parser that accepts documents it will misread -
anchors, multi-document streams, flow collections, block scalars - the loader
supports exactly the shape a policy file needs and rejects everything else with
a message naming the construct. Rejecting a valid-but-unsupported document is
recoverable; misreading it is not.

Supported: comments, ``key: value``, one or two levels of nesting, ``- item``
lists, single/double quoted and bare scalars, booleans, integers. Nothing else.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .policy import Decision, Policy


class PolicyError(ValueError):
    """A policy file is wrong, and running with half of it would be worse.

    Carries the line number when one is known, because "invalid policy" without a
    location sends the reader back to a 40-line file to hunt for it.
    """

    def __init__(self, message: str, line: int | None = None, path: str = "") -> None:
        self.line = line
        self.path = path
        where = f"{path}:{line}" if path and line else (path or "")
        super().__init__(f"{where}: {message}" if where else message)


# --------------------------------------------------------------------------
# A small, strict YAML subset
# --------------------------------------------------------------------------

_TRUE = {"true", "yes", "on"}
_FALSE = {"false", "no", "off"}


def _strip_comment(line: str) -> str:
    """Remove a trailing comment, respecting quotes.

    ``#`` inside a quoted scalar is data, not a comment - a license id like
    ``"GPL-3.0 #1"`` is contrived, but a policy *name* containing ``#`` is not,
    and silently truncating a value is exactly the class of bug this file is
    built to avoid.
    """
    quote = ""
    for index, char in enumerate(line):
        if quote:
            if char == quote:
                quote = ""
        elif char in "\"'":
            quote = char
        elif char == "#":
            return line[:index]
    return line


def _unquote(text: str, line_no: int, path: str) -> str:
    text = text.strip()
    if not text:
        return ""
    if text[0] in "\"'":
        quote = text[0]
        if len(text) < 2 or text[-1] != quote:
            raise PolicyError(f"unterminated quoted value {text!r}", line_no, path)
        return text[1:-1]
    return text


def _scalar(text: str, line_no: int, path: str) -> Any:
    value = _unquote(text, line_no, path)
    lowered = value.lower()
    if lowered in _TRUE:
        return True
    if lowered in _FALSE:
        return False
    if value.lstrip("-").isdigit():
        return int(value)
    return value


def _reject_unsupported(text: str, line_no: int, path: str) -> None:
    """Name the construct instead of guessing what the author meant."""
    stripped = text.strip()
    if stripped in ("---", "..."):
        raise PolicyError(
            "multi-document YAML is not supported; put the policy in one document",
            line_no,
            path,
        )
    if stripped.endswith("|") or stripped.endswith(">"):
        raise PolicyError(
            "block scalars (| and >) are not supported; quote a single-line value",
            line_no,
            path,
        )
    if "&" in stripped or "*" in stripped:
        raise PolicyError(
            "anchors and aliases (& and *) are not supported; write the value twice",
            line_no,
            path,
        )

    # Flow collections must be caught in the *value*, not just at the start of
    # the line: ``accept: {MIT: allow}`` begins with ``accept``, so a
    # startswith check alone let it through and it was stored as the literal
    # string "{MIT: allow}". That is the half-understood document this loader
    # is supposed to refuse, so check the part after the first colon too.
    value = stripped.partition(":")[2].lstrip() if ":" in stripped else ""
    for candidate in (stripped, value):
        if candidate.startswith(("[", "{")):
            raise PolicyError(
                "flow collections ([...] and {...}) are not supported; use indented "
                "'key: value' lines and '- item' list entries",
                line_no,
                path,
            )


@dataclass
class _Parsed:
    """A flat-ish parse result: top-level keys map to scalars or nested dicts."""

    data: dict[str, Any]
    #: line number of each top-level key, for error messages
    lines: dict[str, int]


def parse_yaml_subset(text: str, path: str = "") -> _Parsed:
    """Parse the supported subset, or raise PolicyError naming what went wrong."""
    data: dict[str, Any] = {}
    lines: dict[str, int] = {}
    # The key whose nested block we are inside, and its indent.
    parent: str | None = None
    parent_indent = 0

    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = _strip_comment(raw).rstrip()
        if not line.strip():
            continue
        _reject_unsupported(line, line_no, path)

        indent = len(line) - len(line.lstrip())
        if "\t" in line[:indent]:
            raise PolicyError("tabs are not allowed for indentation; use spaces", line_no, path)
        body = line.strip()

        if body.startswith("- "):
            if parent is None or indent <= parent_indent:
                raise PolicyError(
                    f"list item under {parent!r} may be missing from the file "
                    "(no key to attach it to)" if parent else
                    "list item is not inside a key",
                    line_no,
                    path,
                )
            container = data.setdefault(parent, [])
            if not isinstance(container, list):
                raise PolicyError(
                    f"{parent!r} already holds a value, so it cannot also be a list",
                    line_no,
                    path,
                )
            container.append(_scalar(body[2:], line_no, path))
            continue

        if ":" not in body:
            raise PolicyError(
                f"expected 'key: value', got {body!r}",
                line_no,
                path,
            )

        key, _, value = body.partition(":")
        key = key.strip()
        if not key:
            raise PolicyError("empty key before ':'", line_no, path)
        if not value.strip():
            # Start of a nested block.
            parent = key
            parent_indent = indent
            if indent == 0:
                data.setdefault(key, {})
                lines.setdefault(key, line_no)
            else:
                if not isinstance(data.get(parent), dict):
                    pass
            continue

        if indent == 0:
            data[key] = _scalar(value, line_no, path)
            lines[key] = line_no
            parent = None
        else:
            if parent is None:
                raise PolicyError(
                    f"indented key {key!r} has no parent key above it",
                    line_no,
                    path,
                )
            nested = data.setdefault(parent, {})
            if not isinstance(nested, dict):
                raise PolicyError(
                    f"{parent!r} already holds a scalar, so it cannot also hold "
                    f"nested keys",
                    line_no,
                    path,
                )
            nested[key] = _scalar(value, line_no, path)
            lines.setdefault(f"{parent}.{key}", line_no)

    return _Parsed(data, lines)


# --------------------------------------------------------------------------
# Schema
# --------------------------------------------------------------------------

#: Posture names that ``extends`` may reference. Kept as strings rather than the
#: factory functions so the error message can list them.
BASE_POSTURES = ("commercial", "permissive", "saas", "copyleft")

_TOP_LEVEL = {"extends", "name", "accept", "settings", "note"}
_SETTINGS = {
    "allow_weak_copyleft",
    "allow_strong_copyleft",
    "allow_network_copyleft",
    "max_staleness_days",
    "require_patent_grant",
    "distribution_model",
}
_DISTRIBUTION_MODELS = ("distributed", "saas", "internal")
_DECISIONS = {"allow", "review", "block"}


def _base(name: str) -> Policy:
    if name == "commercial":
        return Policy()
    if name == "permissive":
        return Policy.permissive_only()
    if name == "saas":
        return Policy.saas()
    if name == "copyleft":
        return Policy.copyleft_ok()
    raise AssertionError(name)


def _require_mapping(data: dict, key: str, parcel: "_Parsed", path: str,
                     what: str) -> dict:
    """Get a nested block, or explain the two ways it is usually written wrong.

    A scalar here is almost always one of two things: flow style
    (``accept: {MIT: allow}``) or a value typed on the same line as the key
    followed by indented lines that then belong to nothing. Both produce a
    string where a mapping was expected, and until this helper existed the
    message was "must be a mapping, not a single value" - true, but it did not
    tell the author which of the two they had done.
    """
    value = data.get(key)
    if value is None or value == {}:
        return {}
    if isinstance(value, dict):
        return value
    text = str(value).strip()
    if text.startswith(("{", "[")):
        raise PolicyError(
            f"{key}: {what} must be a nested block, not flow style. Write one "
            f"'id: value' line per entry, indented under '{key}:'.",
            parcel.lines.get(key),
            path,
        )
    if text:
        raise PolicyError(
            f"{key}: {what} must be a nested block, but this line has a value "
            f"({text!r}) on the key itself. Leave the line as '{key}:' with "
            "nothing after the colon, then indent the entries below it.",
            parcel.lines.get(key),
            path,
        )
    raise PolicyError(
        f"{key}: {what} must be a nested block.",
        parcel.lines.get(key),
        path,
    )


def _check_unknown(keys: set[str], allowed: set[str], where: str, parcel: _Parsed) -> None:
    """Reject unknown keys, suggesting the closest known one.

    This is the single most important check in the module. A misspelled
    ``allow_strong_copyeft`` parses fine, changes nothing, and leaves the team
    certain they relaxed a rule they did not relax.
    """
    for key in sorted(keys - allowed):
        suggestion = _closest(key, allowed)
        hint = f" — did you mean {suggestion!r}?" if suggestion else ""
        line = parcel.lines.get(f"{where}.{key}") or parcel.lines.get(key)
        raise PolicyError(
            f"unknown key {key!r}{hint} (allowed: {', '.join(sorted(allowed))})",
            line,
            "",
        )


def _closest(word: str, candidates: set[str]) -> str:
    """Nearest candidate for the "did you mean" hint.

    Uses difflib from the stdlib - it is a dependency already, and a character-set
    overlap heuristic is actively misleading here: ``GPL-3.0-only`` shares more
    *letters* with ``AGPL-3.0`` than with ``GPL-3.0``, so the crude version
    suggested the wrong license to someone who had already typed the right one
    minus a suffix. Wrong suggestions in an error message are worse than none.
    """
    import difflib

    matches = difflib.get_close_matches(word, sorted(candidates), n=1, cutoff=0.6)
    return matches[0] if matches else ""


def _decision(value: Any, line: int | None, what: str, path: str = "") -> Decision:
    if isinstance(value, bool):
        # ``MIT: yes`` reads like "yes, allowed" but parses as a boolean. Guessing
        # which decision was meant would be inventing a policy, so name the fix.
        raise PolicyError(
            f"{what}: {value!r} is a boolean, not a decision. Write allow, review "
            "or block.",
            line,
            path,
        )
    text = str(value).strip().lower()
    if text == "warn":
        # A common synonym; map it rather than reject, but say so in the docs.
        text = "review"
    if text not in _DECISIONS:
        raise PolicyError(
            f"{what}: {value!r} is not a decision (use allow, review or block)",
            line,
            path,
        )
    return Decision(text)


def _known_license_ids() -> set[str]:
    """SPDX ids plus the two pseudo-ids the judge emits."""
    from .judge import PROFILE_BY_ID

    return set(PROFILE_BY_ID) | {"NONE", "UNRECOGNIZED", "CUSTOM"}


def load_policy_file(path: str | Path) -> Policy:
    """Read a policy file into a Policy, or raise PolicyError explaining why not."""
    path = Path(path)
    if not path.exists():
        raise PolicyError(f"no such policy file: {path}")
    text = path.read_text(encoding="utf-8")
    parcel = parse_yaml_subset(text, str(path))
    data = parcel.data

    _check_unknown(set(data), _TOP_LEVEL, "", parcel)

    base_name = str(data.get("extends", "commercial")).strip()
    if base_name not in BASE_POSTURES:
        raise PolicyError(
            f"extends: {base_name!r} is not a posture "
            f"(use one of: {', '.join(BASE_POSTURES)})",
            parcel.lines.get("extends"),
            str(path),
        )
    policy = _base(base_name)

    # -- accept: explicit per-license decisions ------------------------------
    accept = _require_mapping(
        data, "accept", parcel, str(path),
        "a mapping of license id to decision",
    )
    known = _known_license_ids()
    overrides: dict[str, Decision] = {}
    for license_id, value in (accept or {}).items():
        license_id = str(license_id).strip()
        if license_id not in known:
            suggestion = _closest(license_id, known)
            hint = f" — did you mean {suggestion!r}" if suggestion else ""
            raise PolicyError(
                f"accept: {license_id!r} is not a license id this tool can emit"
                f"{hint}. A misspelled id would never match, so it is refused "
                "rather than ignored.",
                parcel.lines.get(f"accept.{license_id}"),
                str(path),
            )
        overrides[license_id] = _decision(
            value,
            parcel.lines.get(f"accept.{license_id}"),
            f"accept.{license_id}",
            str(path),
        )

    # -- settings ------------------------------------------------------------
    settings = _require_mapping(
        data, "settings", parcel, str(path), "a mapping of settings",
    )
    _check_unknown(set(settings or {}), _SETTINGS, "settings", parcel)

    updates: dict[str, Any] = {}
    for key, value in (settings or {}).items():
        line = parcel.lines.get(f"settings.{key}")
        if key in ("allow_weak_copyleft", "allow_strong_copyleft",
                   "allow_network_copyleft", "require_patent_grant"):
            if not isinstance(value, bool):
                raise PolicyError(
                    f"settings.{key}: expected true or false, got {value!r}",
                    line,
                    str(path),
                )
            updates[key] = value
        elif key == "max_staleness_days":
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise PolicyError(
                    f"settings.max_staleness_days: expected a positive integer, "
                    f"got {value!r}",
                    line,
                    str(path),
                )
            updates[key] = value
        elif key == "distribution_model":
            text_value = str(value).strip().lower()
            if text_value not in _DISTRIBUTION_MODELS:
                raise PolicyError(
                    f"settings.distribution_model: {value!r} is not one of "
                    f"{', '.join(_DISTRIBUTION_MODELS)}",
                    line,
                    str(path),
                )
            updates[key] = text_value

    # -- assemble ------------------------------------------------------------
    name = str(data.get("name") or path.stem).strip() or path.stem
    # A policy that says it extends ``saas`` but then accepts AGPL contradicts
    # itself. Not an error - legal teams do sign off on specific components -
    # but the name must not keep claiming a posture it no longer follows.
    if overrides and name == base_name:
        name = f"{base_name}+overrides"

    policy = Policy(
        name=name,
        allowed=policy.allowed,
        allow_weak_copyleft=updates.get("allow_weak_copyleft", policy.allow_weak_copyleft),
        allow_strong_copyleft=updates.get("allow_strong_copyleft", policy.allow_strong_copyleft),
        allow_network_copyleft=updates.get("allow_network_copyleft", policy.allow_network_copyleft),
        max_staleness_days=updates.get("max_staleness_days", policy.max_staleness_days),
        require_patent_grant=updates.get("require_patent_grant", policy.require_patent_grant),
        distribution_model=updates.get("distribution_model", policy.distribution_model),
        overrides=overrides,
        source=str(path),
    )
    return policy


def dumps_policy(policy: Policy) -> dict:
    """Serialise a policy for --json output, so a report can be reproduced.

    The file path alone is not enough: the file can change under a report that
    was already signed off. The overrides are inlined so the report carries the
    policy it was judged against.
    """
    return {
        "name": policy.name,
        "source": policy.source,
        "allow_weak_copyleft": policy.allow_weak_copyleft,
        "allow_strong_copyleft": policy.allow_strong_copyleft,
        "allow_network_copyleft": policy.allow_network_copyleft,
        "max_staleness_days": policy.max_staleness_days,
        "require_patent_grant": policy.require_patent_grant,
        "distribution_model": policy.distribution_model,
        "overrides": {k: v.value for k, v in sorted(policy.overrides.items())},
    }


def describe(policy: Policy) -> str:
    """One-line summary for stderr, so a run says which policy it used."""
    parts = [f"policy {policy.name}"]
    if policy.source:
        parts.append(f"from {policy.source}")
    if policy.overrides:
        decided = ", ".join(f"{k}={v.value}" for k, v in sorted(policy.overrides.items()))
        parts.append(f"overrides [{decided}]")
    return " · ".join(parts)


def policy_to_json(path: str | Path) -> str:
    return json.dumps(dumps_policy(load_policy_file(path)), indent=2, ensure_ascii=False)