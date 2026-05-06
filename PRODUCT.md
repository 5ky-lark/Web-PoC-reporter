# PRODUCT — CyberSyc

## What it is

A web vulnerability scanner that produces **deliverable, reproducible Proof-of-Concept reports** for offensive-security testing. Not a SaaS demo. The output is an artifact a pentester signs and hands to a client.

## Register

`product` — internal operator tool. Information density before decoration. Decisions over prettiness.

## Users

A pentester or AppSec engineer **mid-engagement, late at night, two monitors, a terminal already open**. They are tired and need to triage 40+ findings inside a 90-minute window without losing their place. They scan multiple targets, switch contexts often, and care about **reproducibility and audit trail** more than aesthetics.

Secondary: the AppSec lead who reviews findings the next day, marks false-positives, and exports SARIF for the dev team's GitHub Security tab.

## Strategic principles

1. **Reproducibility over prose.** Every finding ships a raw HTTP request, raw response, and a one-line `curl`. The PoC is replayable, not described.
2. **Severity must be derived, not asserted.** CVSS vector → severity, every time. Operators can override with a recorded justification.
3. **Persistence is non-negotiable.** Every scan, every request issued, every status change is on disk. A reporter without history is a scanner.
4. **Diff is the headline feature.** "What changed since last time" is the question every client asks. Make it the front page.
5. **The legal trail is part of the product.** Authorization confirmation, tester identity, and an append-only audit log are first-class data.
6. **Operators triage, the system stays out of the way.** Dense layouts, keyboard-first, no animation theatre, no gradient decoration.

## Anti-references

What this is not, and what its UI must not look like:

- **Not Linear / Stripe / Vercel cream-purple SaaS.** No purple→magenta gradient. No gradient text. No giant hero with "Built by [logos]".
- **Not the dark-blue + neon-green "hacker" cliché.** No matrix rain, no Anonymous mask, no terminal-emulator theatre.
- **Not Splunk / Datadog dashboard maximalism.** No 30-widget grid, no decorative sparklines on every cell.
- **Not the iOS-glass / glassmorphism aesthetic.** No `backdrop-filter` decoration. No "frosted" panels.
- **Not Burp Suite's Java desktop UI.** Web-native, not a port.

## Brand voice

Direct, operator-to-operator. Active verbs. No marketing fluff. No "comprehensive" or "professional" or "industry-leading". Headings are nouns or imperatives ("Triage", "Run a scan"). Errors are specific ("Target returned 503 for 4/12 probes — server may be rate-limiting; consider Stealth mode" not "Something went wrong").

No em-dashes. Use commas, colons, periods.

## Three primary surfaces

1. **Run** — target + profile (Recon / Standard / Deep) + advanced module toggles + start. Includes the live progress feed and kill switch when a scan is in flight.
2. **Triage** — findings table, severity ladder, search/filter/sort/group, right-pane detail with raw HTTP/curl/PoC/notes/history.

## Scope cut for this build

Shipping now: persistence, raw PoC capture, CVSS calculator + derived severity, operator workflow (status/notes/override), SARIF/JSON/MD/CSV exports, scan diff, throttling, kill switch, full UI rebuild.

Deferred (next round): headless browser (Playwright) for DOM-XSS and login recipes, Burp/mitmproxy passthrough, multi-step CSRF flows, JIRA/Linear sync, multi-pentester collaboration, SLA aging.
