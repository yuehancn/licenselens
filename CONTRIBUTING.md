# Contributing

Thanks for considering it. This project is small and the bar is high on one
thing: **a wrong license answer is worse than no answer.**

## The one rule

If you change how a license is detected, add a regression test that uses real
license text. Not a paraphrase, not a snippet you typed from memory — the actual
document. The fixtures in `tests/fixtures/` were fetched verbatim from the
GitHub Licenses API and the SPDX license list for exactly this reason.

A test that only proves your regex matches your own string proves nothing.

## Ground rules for the judge

The judge is deliberately structured, and these properties are load-bearing.
Please do not "simplify" them:

1. **Position-aware matching.** Signals declare `REGION_HEAD` or `REGION_BODY`.
   Title evidence may only fire in the head. This is what stops GPL-3.0 from
   being classified as AGPL-3.0, because GPL-3.0 section 13 *mentions* the
   Affero license by name.
2. **Weights, not ordering.** Do not replace the weighted scorer with an
   `if/elif` chain. Ordering bugs are invisible until they are expensive, and
   `test_verdicts_are_order_independent` exists to enforce this.
3. **Shared clauses carry no discriminative weight.** Clause 1 and 2 of BSD-2
   and BSD-3 are identical. They must not outscore clause 3, or every BSD-3 file
   resolves to BSD-2. See `_shared_patterns()`.
4. **Doubt is a feature.** If the top score is close to the runner-up, return
   `decisive=False` and say so. Do not tune weights until every input produces a
   confident answer; some inputs genuinely are ambiguous.
5. **Never guess.** An unrecognized license must come back as unrecognized. Do
   not add a catch-all that assumes permissive.

## Adding a license

1. Fetch the canonical text into `tests/fixtures/` (keep it verbatim).
2. Add a `Profile` with at least one `REGION_HEAD` signal and at least one
   `REGION_BODY` signal, plus `commercial`, `copyleft` and `obligations`.
3. If it comes in variants (Creative Commons, or a vendor's "fair-code" license),
   prefer family detection plus modifiers over one profile per variant.
4. Add it to `CANONICAL` in `tests/test_all.py`.
5. Run `python licenselens.py selftest`.

If the license is a proprietary or research-only rider, add it to
`_CUSTOM_SIGNALS` and make sure `commercial` becomes `forbidden` — a custom
rider always overrides permissive-sounding wording above it.

## Running things

```bash
python licenselens.py selftest          # full suite, no dependencies
python licenselens.py selftest judge    # filter by name
python licenselens.py judge LICENSE     # classify a file
python licenselens.py scan . --resolve  # audit this repo's dependencies
```

No `pip install` is required for development or testing. That is intentional:
the suite has to run on the machines where this tool is most needed, which are
frequently the ones where installing packages is not allowed.

If you do publish, note the naming split: the PyPI distribution is
`licenselens-cli`, the import package and console script are `licenselens`.
`licenselens` on PyPI is an unrelated project — publishing under that name is
impossible, and telling users to `pip install licenselens` installs the wrong
tool. Never "fix" this by renaming the import package; that would break every
existing `import licenselens` and the console script name in people's CI configs.

## Code style

- Python 3.10+. No third-party runtime dependencies, ever. The tool must run on a
  locked-down CI runner with nothing but CPython.
- Type annotations on public functions.
- Comments explain *why*, especially where a line looks odd because it works
  around a real GitHub response. "GitHub removed the textarea in 2025" is a
  useful comment; "extract the lines" is not.
- Network code must have a timeout, and must degrade instead of raising into the
  user's face.

## Contributor License Agreement

Because this project is dual-licensed (AGPL-3.0 plus a commercial license), the
maintainer needs the right to license contributions under both. By opening a pull
request you agree that:

1. You have the right to submit the contribution.
2. You grant the maintainer a perpetual, worldwide, non-exclusive, royalty-free,
   irrevocable license to use, reproduce, modify, distribute, sublicense and
   **relicense** your contribution, including under commercial terms.
3. You retain copyright ownership of your contribution. This is a license, not an
   assignment.
4. Your contribution is provided "as is", without warranty.

If you are contributing on behalf of an employer, confirm you are permitted to.
If you cannot agree to point 2, please open an issue instead of a pull request —
we can still use the idea, and a bug report is genuinely valuable.

## Reporting a wrong verdict

This is the most valuable contribution you can make. Please include:

- the repository or a copy of the license text;
- what the tool said;
- what the license actually is, and the clause that proves it.

A confirmed misclassification gets fixed and a regression test added, and you get
credited in the commit.