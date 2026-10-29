# Commercial licensing

`licenselens` is dual-licensed. You may use it under either of the following, at
your choice:

1. **The GNU Affero General Public License v3.0** (see [`LICENSE`](LICENSE)) —
   free of charge, for any purpose, including commercial use.
2. **A commercial license** — for use where the AGPL's source-disclosure
   obligation does not fit your business.

You do not need to buy anything to use this tool inside your company. Read the
next section before assuming you do.

---

## When the AGPL is already enough (no purchase needed)

The AGPL's obligations trigger on **distribution** and on **providing the
software to users over a network**. If neither happens, the AGPL costs you
nothing beyond keeping the license notice. In practice that covers most uses:

| How you use it | AGPL sufficient? |
| --- | --- |
| Run `licenselens` locally or in your own CI | **Yes** — no distribution, no network service |
| Use it internally on a team server that only staff reach | **Yes** — internal use is not conveying |
| Audit your own dependencies before a release | **Yes** |
| Ship it inside a product you distribute to customers | **No** — see commercial license |
| Offer it as part of a hosted service your customers log into | **No** — the network clause applies |
| Embed it in a closed-source tool you resell | **No** |

If you are in the "Yes" column, stop here. The AGPL is a real grant; this page
exists for the cases it does not cover.

## When you need the commercial license

A commercial license removes the AGPL's copyleft obligations. Specifically it
grants you the right to:

- integrate `licenselens` into a **closed-source** product and distribute that
  product without releasing your own source;
- operate it as part of a **hosted or SaaS offering** without publishing your
  service code;
- **relicense** the integration to your own customers, and use it in a product
  whose license terms are incompatible with the AGPL;
- receive a **written warranty of title** and an indemnity that the AGPL does not
  provide;
- use the **commercial-only modules** (see below), which are not part of the
  open-source distribution.

It does not grant trademark rights, and it does not remove your obligation to
comply with the licenses of the *dependencies you audit* — this tool reports on
other licenses, it does not license them to you.

---

## What is open source and what is not

Everything in this repository is AGPL-3.0-or-later. That is the whole tool:
judge, probe, policy, report, CLI, registry resolver.

Commercial-only work, developed separately and **not** in this repository:

- organisation-wide policy packs and approval workflows
- continuous monitoring with change alerts when an upstream license shifts
- SBOM ingestion and policy gates for CycloneDX / SPDX documents
- signed audit reports for procurement and due-diligence review
- priority support with a response-time commitment

The open-source tool is complete and useful on its own. The commercial layer
exists for teams that need it operated, attested, or wired into a process.

## Tiers

Prices are in CNY and exclude tax. Annual, billed in advance. Seat counts are
named users who run the tool or read its reports.

| | **Team** | **Business** | **Enterprise** |
| --- | --- | --- | --- |
| Price / year | ¥3,800 | ¥12,800 | from ¥48,000 |
| Named seats | 5 | 25 | unlimited |
| Closed-source distribution | yes | yes | yes |
| SaaS / hosted use | yes | yes | yes |
| Rebranding | no | yes | yes |
| Policy packs | 1 | 5 | unlimited |
| CI integration support | email | email + call | dedicated |
| Signed audit reports | no | 4 / year | unlimited |
| Response commitment | best effort | 3 business days | 1 business day |
| Security questionnaire support | no | yes | yes |
| Source escrow | no | no | optional |

**Startup / individual discount:** 80% off Team for companies under 5 people and
under ¥1,000,000 annual revenue, for the first two years. No application form —
say so in your email and it applies.

**Open-source projects and academic research:** free commercial license. If your
project is itself AGPL-compatible or your use is non-commercial research, you
already have everything you need; ask only if you want the warranty.

## How to buy

Email **`licenselens@outlook.com`** with:

1. legal entity name and country;
2. the tier you want;
3. the number of seats;
4. how you will use it (distributed product / hosted service / internal).

You get an invoice and a license agreement. Nothing is metered, phoned home, or
revocable at our convenience: the license key is a document, not a server.

## Why dual licensing instead of "open core with a crippled free tier"

Because a compliance tool that hides its logic is worthless. The whole value of
this tool is that you can read why it decided something, and verify it against
the license text yourself. Gating the judge behind a paywall would make the
answer unauditable, which defeats the purpose. So the judge is open, complete,
and free — and the license fee buys the things a company needs around it:
indemnity, attestation, and someone to call.

## Contributor licensing

To keep dual licensing legally possible, contributions require a CLA that grants
the maintainer the right to license the contribution commercially. See
[`CONTRIBUTING.md`](CONTRIBUTING.md). This is the standard arrangement for dual-
licensed projects; it is not a copyright assignment, and you keep ownership of
your work.

## Questions this page does not answer

If your situation is not on this page, email and ask. A one-line description of
what you want to do is enough, and the answer is free. Getting this wrong in
either direction is expensive — for you legally, and for the project
commercially — so it is worth the email.

---

*This document is a commercial summary, not legal advice. The binding terms are
in the license agreement you sign.*