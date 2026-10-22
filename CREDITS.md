# Credits

**Author and maintainer:** Jens Miltenberger, Director Consulting Services, ceterion AG. Working with Citrix appliances since 2004, from the Net6 Access Gateway through Citrix's acquisition of NetScaler to today's ADC and Gateway builds. His field is end-user computing as a whole: secure access (NetScaler Gateway, Citrix and Microsoft identity), the workplace (Citrix Virtual Apps and Desktops, Microsoft 365, Azure, Intune) and application lifecycle management, today with Recast Application Workspace for packaging, deployment and updates. This project covers the first of those layers. Design, script, rules-file format, workflow, test data and documentation, as well as the companion tools `netscaler-snapshot` (sh, on the appliance) and `netscaler-collector` (PowerShell 7, off the appliance). The script runs daily on the author's lab and customer gateways; the findings behind the rules and test data come from those runs.

**On the use of AI:** The toolset was built in two weeks, from the first bulletin to this release, with an AI assistant (Claude, Anthropic) as a working partner for design, code, test data and documentation. The point was to show that defenders can move at the same speed as the people on the other side, who use the same tools: **the Force is not only strong with the dark side**. What the assistant could not do, and did not: decide what counts as evidence. Every indicator in the rules file is traced to its primary publisher, every change runs through the test suite, and every finding described here was checked on real appliances before it became a rule. **May the Force be with you, and with your gateways.**

Contact: netscaler-integrity@ceterion.com
Author on LinkedIn: https://www.linkedin.com/in/jensmiltenberger/ . Connections and followers welcome; that is where new rules stands, findings from the field and the next releases get announced first.

netscaler-quickcheck is published by ceterion AG under Apache 2.0. The indicators in the rules file are facts published by the sources named below; every line names its publisher.

## Primary sources

Every value in the rules file names its publisher on its own line; `ns_quickcheck.rules.provenance.md` lists them all and is regenerated at every release. This table is checked against it at every release.

| Publisher | What we use | Lines today |
|---|---|---|
| CISA, Code & Media Analysis | consolidated indicator list for CVE-2026-88771 and 88772 (addresses, domains, hashes, paths), SIGMA rule 261399 r1, TLP:CLEAR | 73 |
| Citrix (Cloud Software Group) | CVE table: fix builds and configuration conditions from CTX697096, CTX697174, CTX697191 | 40 |
| Palo Alto Networks, Unit 42 | pre-disclosure activity, exploit chain, web shell analysis, addresses and hashes | 23 |
| LevelBlue SpiderLabs | post-exploitation files under LogonPoint, login-name injection variants, addresses | 5 |
| Mandiant / Google Threat Intelligence Group | DTLS exploitation chain, SLAPSHOT and WHIPSHOT artefacts and addresses | 4 |
| SOCRadar | C2 framework, polling agent, DNS out-of-band pattern | 3 |
| watchTowr Labs | post-exploitation artefacts (user, listener, dropbear), addresses | 2 |
| Sygnia | payload path from the advisory of 2026-10-01 | 1 |
| CERT-EU | the first published log line of the CVE-2026-88771 injection chain; basis of the log patterns | patterns |
| CISA, Known Exploited Vulnerabilities | exploitation status | status |

Consulted, no values taken yet (their values stay inactive until the reference check confirms a primary publication): Arctic Wolf, Beazley Security Labs, Huntback.io, TENEX, PitScaler (timeline and cross-reference).

## What is not used

Indicator blocks that other tools carry under a restricted permission from third parties are not used. Every value in the rules file names its original publisher with URL and date; values that cannot be traced to a primary publication stay inactive. For the widest address coverage, running a community checker alongside netscaler-quickcheck is a reasonable choice.

## How to be listed

If your published research is used in the rules file, you are named per line and in the changelog. If something is missing or attributed wrongly, open an issue or write to netscaler-integrity@ceterion.com.
