"""Dependency manifest scanning.

The repository audit answers "is this project safe to depend on?". This module
answers the question that actually gates a release: "what does *my* project
already depend on, and which of those will hurt me?"

It reads manifests, not lockfiles, because the license question is about the
declared dependency set. Lockfiles pin versions but never carry license terms,
and parsing every ecosystem's lock format is a large surface for little gain.
SBOM inputs (``package.json``'s ``license`` field, ``pyproject.toml``
classifiers, ``*.dist-info/METADATA``) already state the license, so we read it
where it exists and fall back to the registry only when it does not.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .judge import Verdict, judge_expression
from .policy import Decision, Finding, Policy, evaluate

try:  # Python 3.11+
    import tomllib as _toml
except ModuleNotFoundError:  # pragma: no cover - 3.10 fallback
    _toml = None


@dataclass
class ManifestEntry:
    name: str
    version_spec: str = ""
    license_declared: str = ""
    ecosystem: str = ""
    source_file: str = ""
    verdict: Verdict | None = None
    decision: Decision = Decision.REVIEW
    findings: list[Finding] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version_spec": self.version_spec,
            "ecosystem": self.ecosystem,
            "license_declared": self.license_declared,
            "source_file": self.source_file,
            "decision": self.decision.value,
            "license": self.verdict.to_dict() if self.verdict else None,
            "findings": [f.to_dict() for f in self.findings],
            "note": self.note,
        }


#: Directories that never contain first-party manifests worth auditing.
_SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
    ".tox", ".mypy_cache", ".pytest_cache", "site-packages", ".next", "target",
    "vendor", "third_party",
}


def discover_manifests(root: Path, *, max_depth: int = 4) -> list[Path]:
    """Find dependency manifests under ``root``, shallow-first."""
    names = {
        "package.json", "pyproject.toml", "setup.py", "requirements.txt",
        "composer.json", "Cargo.toml", "go.mod", "Gemfile",
    }
    found: list[Path] = []
    root = root.resolve()
    for path in sorted(root.rglob("*")):
        if len(path.relative_to(root).parts) > max_depth:
            continue
        if any(part in _SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if path.is_file() and path.name in names:
            found.append(path)
    return found


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


_SPEC_CHARS = re.compile(r"^[\^~><=!*\s\d.\-+|]+$")


def _parse_package_json(path: Path) -> list[ManifestEntry]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return []
    entries: list[ManifestEntry] = []

    own = data.get("license")
    if isinstance(own, str):
        entries.append(ManifestEntry(
            name=data.get("name", path.parent.name),
            version_spec=data.get("version", ""),
            license_declared=own,
            ecosystem="npm",
            source_file=str(path),
            note="this project",
        ))

    for section in ("dependencies", "devDependencies", "peerDependencies",
                    "optionalDependencies"):
        for name, spec in (data.get(section) or {}).items():
            if not isinstance(spec, str):
                continue
            # A local path or a git URL has no registry license to read.
            if spec.startswith(("file:", "link:", "git", "http", "workspace:")):
                continue
            entries.append(ManifestEntry(
                name=name,
                version_spec=spec,
                ecosystem="npm",
                source_file=str(path),
                note=section,
            ))
    return entries


def _strip_requirement(line: str) -> tuple[str, str] | None:
    line = line.split("#", 1)[0].strip()
    if not line or line.startswith("-"):
        return None
    match = re.match(r"^([A-Za-z0-9_.\-]+)\s*(\[[^\]]*\])?\s*(.*)$", line)
    if not match:
        return None
    return match.group(1), match.group(3).strip()


def _parse_requirements(path: Path) -> list[ManifestEntry]:
    entries: list[ManifestEntry] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parsed = _strip_requirement(line)
        if parsed is None:
            continue
        name, spec = parsed
        if name.lower() in ("pip", "setuptools", "wheel"):
            continue
        entries.append(ManifestEntry(
            name=name, version_spec=spec, ecosystem="pypi", source_file=str(path),
        ))
    return entries


_CLASSIFIER_LICENSE = re.compile(r"License\s*::\s*(.+)$", re.I)


def _parse_pyproject_minimal(text: str) -> dict:
    """Extract ``[project]`` fields from a pyproject.toml without tomllib.

    Scope is deliberately narrow: name, version, license (string or table), and
    the ``dependencies`` / ``classifiers`` arrays. That is everything the scanner
    needs. A partial reader that returns *something* is better here than a
    dependency, but it must not silently pretend an unparsed license is absent -
    if a ``license`` key exists in any recognised form, it is returned.
    """
    project: dict = {}
    # Restrict to the [project] table so tool-specific keys do not leak in.
    match = re.search(r"^\[project\]\s*$(.*?)(?=^\[|\Z)", text, re.M | re.S)
    body = match.group(1) if match else text

    for key in ("name", "version", "requires-python"):
        found = re.search(rf'^\s*{re.escape(key)}\s*=\s*["\']([^"\']*)["\']', body, re.M)
        if found:
            project[key] = found.group(1)

    # license = "MIT"  |  license = { text = "MIT" }  |  license = { file = "LICENSE" }
    found = re.search(r'^\s*license\s*=\s*(.+)$', body, re.M)
    if found:
        raw = found.group(1).strip()
        if raw.startswith("{"):
            inline = {}
            for key in ("text", "file"):
                sub = re.search(rf'{key}\s*=\s*["\']([^"\']*)["\']', raw)
                if sub:
                    inline[key] = sub.group(1)
            if inline:
                project["license"] = inline
        else:
            literal = re.match(r'^["\'](.*)["\']', raw)
            if literal:
                project["license"] = literal.group(1)

    for key in ("dependencies", "classifiers"):
        found = re.search(rf'^\s*{key}\s*=\s*\[(.*?)\]', body, re.M | re.S)
        if found:
            project[key] = re.findall(r'["\']([^"\']+)["\']', found.group(1))

    return {"project": project} if project else {}


def _parse_pyproject(path: Path) -> list[ManifestEntry]:
    text = path.read_text(encoding="utf-8", errors="replace")
    entries: list[ManifestEntry] = []
    data: dict = {}

    if _toml is not None:
        try:
            data = _toml.loads(text)
        except Exception:  # noqa: BLE001 - a malformed manifest must not abort a scan
            data = {}
    else:
        # Python < 3.11 has no tomllib and this tool refuses to depend on a
        # third-party TOML parser. Fall back to pulling the handful of fields
        # that matter out of the [project] table. Not a general TOML parser:
        # it handles the flat key/value and single-line-array forms that real
        # pyproject files use for name, version, license and dependencies.
        data = _parse_pyproject_minimal(text)

    project = data.get("project") or {}
    license_value = project.get("license")
    declared = ""
    if isinstance(license_value, str):
        declared = license_value
    elif isinstance(license_value, dict):
        declared = license_value.get("text") or license_value.get("file") or ""
    if not declared:
        for classifier in project.get("classifiers") or []:
            match = _CLASSIFIER_LICENSE.search(str(classifier))
            if match:
                declared = match.group(1)
                break

    if declared:
        entries.append(ManifestEntry(
            name=project.get("name", path.parent.name),
            version_spec=project.get("version", ""),
            license_declared=declared,
            ecosystem="pypi",
            source_file=str(path),
            note="this project",
        ))

    for dep in project.get("dependencies") or []:
        parsed = _strip_requirement(str(dep))
        if parsed:
            entries.append(ManifestEntry(
                name=parsed[0], version_spec=parsed[1],
                ecosystem="pypi", source_file=str(path),
            ))

    for group in (project.get("optional-dependencies") or {}).values():
        for dep in group:
            parsed = _strip_requirement(str(dep))
            if parsed:
                entries.append(ManifestEntry(
                    name=parsed[0], version_spec=parsed[1],
                    ecosystem="pypi", source_file=str(path), note="optional",
                ))
    return entries


def _parse_composer(path: Path) -> list[ManifestEntry]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return []
    entries: list[ManifestEntry] = []
    own = data.get("license")
    if isinstance(own, list):
        own = " OR ".join(str(x) for x in own)
    if isinstance(own, str) and own:
        entries.append(ManifestEntry(
            name=data.get("name", path.parent.name),
            license_declared=own, ecosystem="packagist", source_file=str(path),
            note="this project",
        ))
    for section in ("require", "require-dev"):
        for name, spec in (data.get(section) or {}).items():
            if "/" not in name:
                continue  # php, ext-* and similar are not packages
            entries.append(ManifestEntry(
                name=name, version_spec=str(spec), ecosystem="packagist",
                source_file=str(path), note=section,
            ))
    return entries


def _parse_setup_py(path: Path) -> list[ManifestEntry]:
    """Best-effort extraction; executing setup.py is not an option."""
    text = path.read_text(encoding="utf-8", errors="replace")
    entries: list[ManifestEntry] = []
    match = re.search(r"license\s*=\s*[\"']([^\"']+)[\"']", text)
    name_match = re.search(r"name\s*=\s*[\"']([^\"']+)[\"']", text)
    if match:
        entries.append(ManifestEntry(
            name=name_match.group(1) if name_match else path.parent.name,
            license_declared=match.group(1),
            ecosystem="pypi",
            source_file=str(path),
            note="this project",
        ))
    return entries


_PARSERS = {
    "package.json": _parse_package_json,
    "requirements.txt": _parse_requirements,
    "pyproject.toml": _parse_pyproject,
    "composer.json": _parse_composer,
    "setup.py": _parse_setup_py,
}


def scan_manifests(
    root: Path,
    policy: Policy | None = None,
    *,
    fetcher=None,
    resolve_remote: bool = False,
    max_lookups: int = 200,
) -> list[ManifestEntry]:
    """Read every manifest under ``root`` and classify declared licenses.

    Entries without a declared license are marked for review rather than
    guessed: an npm dependency's ``license`` field is usually present, and when
    it is absent the honest answer is "unknown, go look".

    Pass ``resolve_remote=True`` to fill those gaps from the package registry.
    That is what makes the report usable on a real dependency tree - manifests
    almost never state their dependencies' licenses - but it costs one request
    per package, so ``max_lookups`` caps the work and it is off by default.
    """
    policy = policy or Policy()
    entries: list[ManifestEntry] = []
    seen: set[tuple[str, str]] = set()

    for manifest in discover_manifests(root):
        parser = _PARSERS.get(manifest.name)
        if parser is None:
            continue
        try:
            parsed = parser(manifest)
        except Exception as exc:  # noqa: BLE001 - keep scanning other manifests
            entries.append(ManifestEntry(
                name=manifest.name, source_file=str(manifest),
                note=f"could not parse: {type(exc).__name__}",
                decision=Decision.REVIEW,
            ))
            continue

        for entry in parsed:
            key = (entry.name.lower(), entry.source_file)
            if key in seen:
                continue
            seen.add(key)
            if entry.license_declared:
                entry.verdict = judge_expression(entry.license_declared)
                entry.decision, entry.findings = evaluate(entry.verdict, policy)
            else:
                entry.note = (entry.note + " | license not declared").lstrip(" |")
            entries.append(entry)

    if resolve_remote and fetcher is not None:
        _resolve_missing(entries, fetcher, policy, max_lookups)
    return entries


def _resolve_missing(entries: list[ManifestEntry], fetcher, policy: Policy,
                     max_lookups: int) -> None:
    """Fill in licenses from the registry for entries that declared none."""
    from .registry import clean_version, resolve

    pending = [
        e for e in entries
        if not e.license_declared and e.ecosystem
        and "this project" not in e.note
    ]
    for entry in pending[:max_lookups]:
        found = resolve(fetcher, entry.ecosystem, entry.name,
                        clean_version(entry.version_spec))
        if chosen := _pick_license_constraint(found):
            entry.license_declared = chosen
            entry.verdict = judge_expression(chosen)
            entry.decision, entry.findings = evaluate(entry.verdict, policy)
            entry.note = (entry.note + f" | resolved from {found.source}").lstrip(" |")
        else:
            entry.note = (
                entry.note + " | registry lookup failed" if found.error
                else entry.note + " | registry has no license field"
            ).lstrip(" | ")


def _pick_license_constraint(found) -> str:
    """Extract something SPDX-shaped from a registry response."""
    if not found or not found.license:
        return ""
    text = str(found.license).strip()
    if not text:
        return ""
    # Some registries return prose. Keep the leading license-looking run.
    if len(text) > 60:
        match = re.search(r"^([A-Za-z0-9.\-+ ]{2,60}?)(?:\s+(?:license|licence)|,|\.|$)",
                          text, re.I)
        text = match.group(1) if match else text[:60]
    return text.strip()