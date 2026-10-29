"""Resolve the license of a published package from its registry.

Manifests rarely state the license of their *dependencies* - only their own. So a
pure offline scan reports "undeclared" for most of a dependency tree, which is
technically honest and practically useless: the engineer still has to go look up
eighty packages.

This module fills that gap by asking the registry, which does know. It is
deliberately conservative:

* Only registries with a stable, documented, key-free JSON endpoint are queried.
* One request per package, cached on disk, so a repeat scan is free.
* Failures degrade to ``unknown`` rather than aborting the scan. A missing
  network must not turn a compliance report into a stack trace.
* Nothing is inferred. If the registry returns no license, the answer stays
  "unknown" - guessing here would defeat the point of the tool.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
from dataclasses import dataclass

from .sources import Fetcher, SourceUnavailable


@dataclass
class RegistryLicense:
    name: str
    version: str = ""
    license: str = ""
    repository: str = ""
    source: str = ""
    error: str = ""

    @property
    def resolved(self) -> bool:
        return bool(self.license)


def _npm(fetcher: Fetcher, name: str, version: str = "") -> RegistryLicense:
    quoted = urllib.parse.quote(name, safe="@")
    url = f"https://registry.npmjs.org/{quoted}/latest" if not version else \
          f"https://registry.npmjs.org/{quoted}/{urllib.parse.quote(version)}"
    try:
        payload = json.loads(fetcher.get(url))
    except SourceUnavailable as exc:
        return RegistryLicense(name=name, version=version, source="npm", error=str(exc))
    except json.JSONDecodeError:
        return RegistryLicense(name=name, version=version, source="npm",
                               error="registry returned non-JSON")

    license_value = payload.get("license")
    if isinstance(license_value, dict):
        license_value = license_value.get("type") or license_value.get("name")
    if not license_value:
        # Older packages use a licenses array or only a README statement.
        licenses = payload.get("licenses") or []
        if isinstance(licenses, list):
            parts = []
            for item in licenses:
                if isinstance(item, dict):
                    parts.append(item.get("type") or "")
                elif isinstance(item, str):
                    parts.append(item)
            license_value = " OR ".join(p for p in parts if p)

    repository = payload.get("repository")
    if isinstance(repository, dict):
        repository = repository.get("url", "")

    return RegistryLicense(
        name=name,
        version=payload.get("version", version),
        license=str(license_value or ""),
        repository=str(repository or ""),
        source="npm",
    )


def _pypi(fetcher: Fetcher, name: str, version: str = "") -> RegistryLicense:
    url = f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json"
    try:
        payload = json.loads(fetcher.get(url))
    except SourceUnavailable as exc:
        return RegistryLicense(name=name, version=version, source="pypi", error=str(exc))
    except json.JSONDecodeError:
        return RegistryLicense(name=name, version=version, source="pypi",
                               error="registry returned non-JSON")

    info = payload.get("info") or {}

    # PEP 639 adds a machine-readable ``license_expression`` field, which is the
    # most reliable source when present. Django, for one, sets only this and
    # leaves the legacy ``license`` field None - reading the old field alone
    # reported "unknown" for the entire Django family.
    license_value = (info.get("license_expression") or "").strip()
    if not license_value:
        license_value = (info.get("license") or "").strip()

    # PyPI's free-text license field is frequently "UNKNOWN" or a whole license
    # paragraph pasted in. The Trove classifiers are the reliable legacy source.
    if not license_value or license_value.upper() in ("UNKNOWN", "NONE"):
        for classifier in info.get("classifiers") or []:
            if isinstance(classifier, str) and "License ::" in classifier:
                tail = classifier.split("License ::")[-1].strip()
                tail = tail.split("::")[-1].strip()
                if tail and "OSI Approved" not in tail:
                    license_value = tail
                    break

    if len(str(license_value)) > 120:
        # A pasted license body: keep the first line, which is the name.
        license_value = str(license_value).split("\n", 1)[0][:120]

    return RegistryLicense(
        name=name,
        version=info.get("version", version),
        license=str(license_value or ""),
        repository=info.get("home_page") or (info.get("project_urls") or {}).get("Source", ""),
        source="pypi",
    )


def _packagist(fetcher: Fetcher, name: str) -> RegistryLicense:
    url = f"https://repo.packagist.org/p2/{urllib.parse.quote(name)}.json"
    try:
        payload = json.loads(fetcher.get(url))
    except SourceUnavailable as exc:
        return RegistryLicense(name=name, source="packagist", error=str(exc))
    except json.JSONDecodeError:
        return RegistryLicense(name=name, source="packagist", error="registry returned non-JSON")

    packages = payload.get("packages") or {}
    versions = packages.get(name) or []
    if not versions:
        return RegistryLicense(name=name, source="packagist", error="not found")

    license_value = versions[0].get("license") or []
    if isinstance(license_value, list):
        license_value = " OR ".join(str(x) for x in license_value)
    return RegistryLicense(
        name=name,
        version=versions[0].get("version", ""),
        license=str(license_value),
        source="packagist",
    )


_RESOLVERS = {
    "npm": _npm,
    "pypi": _pypi,
    "packagist": _packagist,
}


def resolve(
    fetcher: Fetcher,
    ecosystem: str,
    name: str,
    version: str = "",
) -> RegistryLicense:
    resolver = _RESOLVERS.get(ecosystem)
    if resolver is None:
        return RegistryLicense(name=name, version=version, source=ecosystem,
                               error=f"no resolver for {ecosystem}")
    try:
        if ecosystem == "npm":
            return _npm(fetcher, name, version)
        if ecosystem == "pypi":
            return _pypi(fetcher, name, version)
        return _packagist(fetcher, name)
    except Exception as exc:  # noqa: BLE001 - a registry hiccup must not abort a scan
        return RegistryLicense(name=name, version=version, source=ecosystem,
                               error=f"{type(exc).__name__}: {exc}")


def clean_version(spec: str) -> str:
    """Turn a semver range into a concrete version when one is obvious.

    ``^18.2.0`` -> ``18.2.0``, ``>=4.2`` -> ``4.2``, ``==1.0`` -> ``1.0``.
    Anything with an open range or multiple clauses resolves to the latest,
    which is the right default for a license question (licenses rarely change
    within a major line, and the latest is the most likely to differ).
    """
    text = spec.strip()
    for prefix in ("^", "~=", "~", ">=", "==", "=", "v"):
        if text.startswith(prefix):
            text = text[len(prefix):]
    if any(ch in text for ch in ",<*| ") or not text:
        return ""
    return text.strip()