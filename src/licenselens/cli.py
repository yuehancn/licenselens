"""Command line interface.

Two jobs, deliberately kept apart:

``licenselens judge``   classify a license file you already have (offline)
``licenselens audit``   classify the licenses of repositories (network)

The offline half is the one that runs in CI on every pull request, because a
vendored ``LICENSE`` or a ``package.json`` dependency list needs no network call
and no API budget.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .judge import COMMERCIAL_FORBIDDEN, explain, judge, judge_expression
from .policy import Decision, Policy, evaluate, summarize
from .policyfile import (
    PolicyError,
    describe as describe_policy,
    dumps_policy,
    load_policy_file,
)
from .probe import Prober
from .report import _ICON, exit_code, render
from .sources import Fetcher, resolve_token

_POLICIES = {
    "commercial": Policy,
    "closed-source": Policy,
    "permissive": Policy.permissive_only,
    "saas": Policy.saas,
    "copyleft": Policy.copyleft_ok,
}


def _add_policy_args(parser: argparse.ArgumentParser) -> None:
    """Both ways to choose a policy, on every command that takes one.

    ``--policy`` stays for the four built-in postures (short, no file to commit).
    ``--policy-file`` is the M2 addition: the team's deviations live in the repo
    and get code-reviewed like anything else. They are mutually exclusive
    because accepting both invites "which one won?" in a support thread.
    """
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--policy", choices=sorted(_POLICIES), default=None,
        help="built-in commercial posture (default: commercial)",
    )
    group.add_argument(
        "--policy-file", metavar="PATH",
        help="YAML policy file describing what your organisation accepts",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="licenselens",
        description=(
            "Find the licenses that will stop you shipping. Detects copyleft, "
            "non-commercial riders and missing licenses before they reach production."
        ),
        epilog=(
            "Examples:\n"
            "  licenselens judge LICENSE\n"
            "  licenselens judge LICENSE --json\n"
            "  licenselens audit pallets/flask n8n-io/n8n\n"
            "  licenselens audit --file repos.txt --format markdown --policy saas\n"
            "  licenselens audit --file repos.txt --format sarif > licenses.sarif\n"
            "  licenselens expr 'MIT OR GPL-3.0'\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"licenselens {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # -- judge ------------------------------------------------------------
    judge_parser = sub.add_parser(
        "judge", help="classify a local license file (offline)"
    )
    judge_parser.add_argument("paths", nargs="+", help="license files to classify")
    judge_parser.add_argument("--json", action="store_true", help="machine-readable output")
    _add_policy_args(judge_parser)
    judge_parser.add_argument(
        "--quiet", action="store_true", help="print only the SPDX id"
    )
    judge_parser.add_argument(
        "--fail-on",
        choices=["block", "review", "never"],
        default="block",
        help="exit non-zero at this severity (default: block)",
    )

    # -- audit ------------------------------------------------------------
    audit_parser = sub.add_parser(
        "audit", help="classify repositories from GitHub (network)"
    )
    audit_parser.add_argument("repos", nargs="*", help="owner/repo, or full GitHub URLs")
    audit_parser.add_argument("--file", help="read owner/repo lines from a file")
    audit_parser.add_argument(
        "-f", "--format", default="table",
        choices=["table", "markdown", "md", "csv", "json", "sarif"],
        help="output format (default: table)",
    )
    audit_parser.add_argument("-o", "--out", help="write to a file instead of stdout")
    _add_policy_args(audit_parser)
    audit_parser.add_argument(
        "--channel", choices=["auto", "html", "api"], default="auto",
        help="html avoids GitHub API quota entirely (default: auto)",
    )
    audit_parser.add_argument("--cache-dir", help="cache fetched pages here")
    audit_parser.add_argument("--timeout", type=float, default=20.0, help="per-request timeout")
    audit_parser.add_argument("--delay", type=float, default=0.0, help="sleep between repos")
    audit_parser.add_argument(
        "--fail-on", choices=["block", "review", "never"], default="block",
        help="exit non-zero at this severity (default: block)",
    )
    audit_parser.add_argument("--quiet", action="store_true", help="suppress progress output")
    audit_parser.add_argument(
        "--budget", action="store_true", help="report GitHub API budget and exit"
    )

    # -- scan -------------------------------------------------------------
    scan_parser = sub.add_parser(
        "scan", help="audit dependency manifests in a local project (offline)"
    )
    scan_parser.add_argument(
        "path", nargs="?", default=".", help="project root to scan (default: .)"
    )
    scan_parser.add_argument(
        "-f", "--format", default="table",
        choices=["table", "markdown", "md", "json"],
        help="output format (default: table)",
    )
    scan_parser.add_argument("-o", "--out", help="write to a file instead of stdout")
    _add_policy_args(scan_parser)
    scan_parser.add_argument(
        "--fail-on", choices=["block", "review", "never"], default="block",
        help="exit non-zero at this severity (default: block)",
    )
    scan_parser.add_argument(
        "--resolve", action="store_true",
        help="look up undeclared dependency licenses in the package registry",
    )
    scan_parser.add_argument(
        "--cache-dir", help="cache registry responses here",
    )
    scan_parser.add_argument("--quiet", action="store_true")

    # -- expr -------------------------------------------------------------
    expr_parser = sub.add_parser(
        "expr", help="evaluate an SPDX expression such as 'MIT OR Apache-2.0'"
    )
    expr_parser.add_argument("expression", nargs="+", help="one or more SPDX expressions")
    expr_parser.add_argument("--json", action="store_true")

    # -- facts ------------------------------------------------------------
    facts_parser = sub.add_parser(
        "facts", help="show the built-in license knowledge base"
    )
    facts_parser.add_argument("--json", action="store_true")

    # -- policy ----------------------------------------------------------
    policy_parser = sub.add_parser(
        "policy",
        help="check a policy file, or show what a built-in posture means",
    )
    policy_parser.add_argument("path", nargs="?", help="policy file to validate")
    policy_parser.add_argument(
        "--policy", choices=sorted(_POLICIES), default=None,
        help="show a built-in posture instead of reading a file",
    )
    policy_parser.add_argument("--json", action="store_true")
    return parser


# ---------------------------------------------------------------------------


def _policy(args: argparse.Namespace) -> Policy:
    """Resolve --policy / --policy-file into one Policy, or exit 2 explaining why.

    A broken policy file must stop the run. Continuing with the default posture
    would be the worst outcome available: the team believes their exceptions are
    in force, the tool quietly ignores them, and a dependency that was signed off
    gets blocked (or a blocked one ships). Exit 2, not 1, so CI can tell "your
    policy file is broken" apart from "a dependency is blocked".
    """
    path = getattr(args, "policy_file", None)
    if path:
        try:
            return load_policy_file(path)
        except PolicyError as exc:
            print(f"policy error: {exc}", file=sys.stderr)
            raise SystemExit(2) from exc
    name = getattr(args, "policy", None) or "commercial"
    factory = _POLICIES.get(name, Policy)
    return factory()


def _should_fail(decision: Decision, fail_on: str) -> bool:
    if fail_on == "never":
        return False
    if fail_on == "review":
        return decision in (Decision.REVIEW, Decision.BLOCK)
    return decision == Decision.BLOCK


def cmd_judge(args: argparse.Namespace) -> int:
    policy = _policy(args)
    exit_status = 0
    payload: list[dict] = []

    for path_text in args.paths:
        path = Path(path_text)
        if not path.exists():
            print(f"no such file: {path}", file=sys.stderr)
            exit_status = 2
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        verdict = judge(text)
        decision, findings = evaluate(verdict, policy)

        if args.quiet:
            print(verdict.spdx_id)
        elif args.json:
            payload.append({
                "path": str(path),
                "decision": decision.value,
                "verdict": verdict.to_dict(),
                "findings": [f.to_dict() for f in findings],
                # Inlined so a stored report states the policy it was judged
                # against. The file can change afterwards; the report cannot.
                "policy": dumps_policy(policy),
            })
        else:
            print(f"== {path}")
            print(explain(verdict))
            print(f"  decision     {decision.value}")
            print(f"  summary      {summarize(decision, findings)}")
            for finding in findings:
                if finding.severity == Decision.ALLOW:
                    continue
                print(f"    [{finding.severity.value}] {finding.code}: {finding.message}")
                if finding.remedy:
                    print(f"      fix: {finding.remedy}")
            print()

        if _should_fail(decision, args.fail_on):
            exit_status = 1

    if args.json:
        print(json.dumps(payload if len(payload) > 1 else (payload[0] if payload else {}),
                         indent=2, ensure_ascii=False))
    return exit_status


def _read_repo_list(args: argparse.Namespace) -> list[str]:
    repos = list(args.repos or [])
    if args.file:
        path = Path(args.file)
        if not path.exists():
            print(f"no such file: {path}", file=sys.stderr)
            return []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                repos.append(line)
    # de-duplicate, preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for repo in repos:
        key = repo.strip().rstrip("/").lower()
        if key and key not in seen:
            seen.add(key)
            unique.append(repo.strip())
    return unique


def cmd_scan(args: argparse.Namespace) -> int:
    from collections import Counter

    from .manifest import scan_manifests

    root = Path(args.path)
    if not root.exists():
        print(f"no such path: {root}", file=sys.stderr)
        return 2

    policy = _policy(args)

    fetcher = None
    if args.resolve:
        fetcher = Fetcher(timeout=20.0, cache_dir=args.cache_dir)
        if not args.quiet:
            print("resolving undeclared licenses from the registry...", file=sys.stderr)

    entries = scan_manifests(root, policy, fetcher=fetcher,
                             resolve_remote=args.resolve)

    if not entries:
        print(f"no dependency manifests found under {root}", file=sys.stderr)
        return 0

    if args.format == "json":
        output = json.dumps(
            {
                "meta": {"root": str(root), "policy": policy.name,
                         "tool": f"licenselens {__version__}"},
                "entries": [e.to_dict() for e in entries],
            },
            indent=2,
            ensure_ascii=False,
        )
    elif args.format in ("markdown", "md"):
        output = _render_scan_markdown(entries, root)
    else:
        output = _render_scan_table(entries)

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        if not args.quiet:
            print(f"wrote {args.out}", file=sys.stderr)
    else:
        print(output)

    counts = Counter(e.decision for e in entries)
    if args.fail_on == "never":
        return 0
    if args.fail_on == "review":
        return 1 if (counts[Decision.BLOCK] or counts[Decision.REVIEW]) else 0
    return 1 if counts[Decision.BLOCK] else 0


def _render_scan_table(entries) -> str:
    from collections import Counter

    lines = [
        f"{'STATUS':<5} {'PACKAGE':<34} {'LICENSE':<26} {'DECISION':<8} SOURCE",
        "-" * 100,
    ]
    for entry in entries:
        license_id = entry.license_declared or (
            entry.verdict.spdx_id if entry.verdict else "undeclared"
        )
        lines.append(
            f"{_ICON[entry.decision]:<5} {entry.name[:34]:<34} "
            f"{license_id[:26]:<26} {entry.decision.value:<8} "
            f"{Path(entry.source_file).name}"
        )
    counts = Counter(e.decision for e in entries)
    lines.append("-" * 100)
    lines.append(
        f"{len(entries)} packages: {counts[Decision.ALLOW]} allow, "
        f"{counts[Decision.REVIEW]} review, {counts[Decision.BLOCK]} block"
    )
    blocked = [e for e in entries if e.decision == Decision.BLOCK]
    if blocked:
        lines.append("")
        lines.append("Blocking")
        for entry in blocked:
            codes = ", ".join(f.code for f in entry.findings if f.severity == Decision.BLOCK)
            lines.append(f"  {entry.name} ({entry.license_declared}) — {codes}")
            for finding in entry.findings:
                if finding.severity == Decision.BLOCK and finding.remedy:
                    lines.append(f"    fix: {finding.remedy}")
    return "\n".join(lines)


def _render_scan_markdown(entries, root: Path) -> str:
    from collections import Counter

    counts = Counter(e.decision for e in entries)
    out = [
        "# Dependency license report",
        "",
        f"Root: `{root}` · {len(entries)} packages · "
        f"**{counts[Decision.BLOCK]} blocked**, {counts[Decision.REVIEW]} review, "
        f"{counts[Decision.ALLOW]} clear",
        "",
        "| Decision | Package | Declared | Why |",
        "| --- | --- | --- | --- |",
    ]
    for entry in entries:
        if entry.decision == Decision.ALLOW and not entry.license_declared:
            continue
        reason = ""
        severe = [f for f in entry.findings if f.severity == entry.decision]
        if severe:
            reason = severe[0].message.replace("|", "/")[:110]
        elif not entry.license_declared:
            reason = "license not declared in the manifest"
        out.append(
            f"| {entry.decision.value} | `{entry.name}` | "
            f"{entry.license_declared or '-'} | {reason} |"
        )
    return "\n".join(out)


def cmd_audit(args: argparse.Namespace) -> int:
    token, token_source = resolve_token()
    fetcher = Fetcher(timeout=args.timeout, cache_dir=args.cache_dir)

    if args.budget:
        from .probe import check_budget

        print(json.dumps({**check_budget(fetcher, token), "token_source": token_source}, indent=2))
        return 0

    repos = _read_repo_list(args)
    if not repos:
        print("nothing to audit: pass owner/repo arguments or --file", file=sys.stderr)
        return 2

    policy = _policy(args)
    prober = Prober(fetcher=fetcher, token=token, policy=policy, delay=args.delay)

    if not args.quiet:
        channel_note = "HTML channel (no API quota)" if args.channel != "api" else "API channel"
        print(f"Auditing {len(repos)} repositories via {channel_note}", file=sys.stderr)
        if token_source == "none":
            print(
                "  no GitHub token found: HTML channel still works, "
                "API channel is limited to 60 requests/hour",
                file=sys.stderr,
            )

    records = []
    for index, repo in enumerate(repos, 1):
        record = prober.probe(repo, channel=args.channel)
        records.append(record)
        if not args.quiet:
            license_id = record.verdict.spdx_id if record.verdict else "-"
            print(
                f"  [{index:>3}/{len(repos)}] {record.repo[:44]:<44} "
                f"{license_id[:22]:<22} {record.decision.value}",
                file=sys.stderr,
            )

    meta = {
        "tool": f"licenselens {__version__}",
        "policy": policy.name,
        "channel": args.channel,
        "requests": fetcher.stats.requests,
        "cache_hits": fetcher.stats.cache_hits,
        "breaker_trips": fetcher.stats.breaker_trips,
        "token_source": token_source,
    }

    # ``json`` gets audit metadata attached; ``sarif`` is a fixed schema and must
    # not be extended, so the two are rendered separately rather than sharing a
    # branch. Mixing them silently produced empty SARIF output.
    if args.format == "json":
        output = render(records, "json", meta=meta)
    else:
        output = render(records, args.format)

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        if not args.quiet:
            print(f"\nwrote {args.out}", file=sys.stderr)
    else:
        print(output)

    if not args.quiet and fetcher.stats.breaker_trips:
        print(
            f"\nnote: {fetcher.stats.breaker_trips} host(s) tripped the circuit breaker; "
            f"requests to them were skipped instead of hanging",
            file=sys.stderr,
        )

    return exit_code(records) if args.fail_on == "block" else (
        1 if any(_should_fail(r.decision, args.fail_on) for r in records) else 0
    )


def cmd_expr(args: argparse.Namespace) -> int:
    results = []
    for expression in args.expression:
        verdict = judge_expression(expression)
        if args.json:
            results.append(verdict.to_dict())
        else:
            print(explain(verdict))
            print()
    if args.json:
        print(json.dumps(results if len(results) > 1 else results[0], indent=2,
                         ensure_ascii=False))
    return 0


def cmd_facts(args: argparse.Namespace) -> int:
    from .judge import PROFILE_BY_ID

    data = [profile.to_dict() for profile in PROFILE_BY_ID.values()]
    if args.json:
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return 0

    print(f"{'SPDX':<22} {'COMMERCIAL':<13} {'COPYLEFT':<9} PATENT")
    print("-" * 60)
    for profile in PROFILE_BY_ID.values():
        print(
            f"{profile.spdx_id:<22} {profile.commercial:<13} "
            f"{profile.copyleft:<9} {'yes' if profile.patent_grant else 'no'}"
        )
    print()
    print(f"{len(data)} licenses in the knowledge base.")
    return 0


def cmd_policy(args: argparse.Namespace) -> int:
    """Validate a policy file, or print what a posture implies.

    Exists so the policy file can be checked on its own in CI, before any
    dependency is scanned. A broken policy discovered halfway through a 400-package
    audit wastes the audit; discovered in its own job, it is a one-line fix.
    """
    if args.path:
        try:
            policy = load_policy_file(args.path)
        except PolicyError as exc:
            print(f"policy error: {exc}", file=sys.stderr)
            return 2
        status = "ok"
    elif args.policy:
        policy = _policy(args)
        status = "ok"
    else:
        print("give a policy file path, or --policy <name>", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(dumps_policy(policy), indent=2, ensure_ascii=False))
        return 0

    print(f"{status}: {describe_policy(policy)}")
    print(f"  weak copyleft (MPL/LGPL)    "
          f"{'allow' if policy.allow_weak_copyleft else 'review'}")
    print(f"  strong copyleft (GPL)       "
          f"{'allow' if policy.allow_strong_copyleft else 'block'}")
    print(f"  network copyleft (AGPL)     "
          f"{'allow' if policy.allow_network_copyleft else 'block'}")
    print(f"  distribution model          {policy.distribution_model}")
    print(f"  max staleness               {policy.max_staleness_days} days")
    print(f"  require patent grant        "
          f"{'yes' if policy.require_patent_grant else 'no'}")
    if policy.overrides:
        print("  overrides")
        for spdx_id, decision in sorted(policy.overrides.items()):
            print(f"    {spdx_id:<24} {decision.value}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    handlers = {
        "judge": cmd_judge,
        "audit": cmd_audit,
        "scan": cmd_scan,
        "expr": cmd_expr,
        "facts": cmd_facts,
        "policy": cmd_policy,
    }
    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        return 2

    try:
        return handler(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except BrokenPipeError:
        # Happens when output is piped into head. Not an error.
        try:
            sys.stdout.close()
        except Exception:  # noqa: BLE001
            pass
        return 0


if __name__ == "__main__":
    sys.exit(main())