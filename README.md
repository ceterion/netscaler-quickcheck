# netscaler-quickcheck

Deutsch: [README.de.md](README.de.md). Full documentation and runbook: `ns_quickcheck_README.md` (German, leading) and `ns_quickcheck_README.en.md` (English; it quotes the German output lines with their meaning, so a German report can be read with it). **Language:** the script's output (terminal, report, finding texts in the JSON) is German in this release, by design: the tool was built with and for operators in the DACH region, where the report is read by administrators, management and auditors in German, and where a security finding that needs translating before it is understood costs time in the one situation where time matters. Field names, verdicts and the result line are language-neutral and documented in English in `docs/report-format.md`, so machines and non-German readers can still act on a report. An English output option (`--language en`) is planned for V18; the repository front, workflow and format documents are English already. Operator workflow for a new bulletin: [WORKFLOW.md](WORKFLOW.md).

Security triage for Citrix NetScaler ADC and Gateway, run on the appliance: build against the Citrix bulletins, attack traces, compromise quick check, address lists, anonymised reports, one verdict. Rule-driven, offline-capable, extensible with your own indicators. Written in October 2026 for CTX697096, CTX697174 and CTX697191, built for the bulletins that follow.

**Status:** **Validated on NetScaler 14.1** (73.41 and 73.46, lab and customer gateways, October 2026). **13.1 and FIPS trains: beta.** The CVE table, fix builds and all log-based checks (blocks 1 to 4) apply unchanged; what differs per train are the stock states in block 5 (listeners, alias roots, admin command patterns, stock file hashes), which come from 14.1. On 13.1 or FIPS expect yellow findings in block 5 on the first run and an INFO "no stock hash for this build" instead of the hash check; nothing is hidden, the verdict is `INVESTIGATE` until the lists are extended. Confirmed findings go into the whitelist locally; an anonymized first-run report (`ns_quickcheck_README.md`, 5.3) sent to the contact address lets us extend the stock lists for everyone. Part 1 of 3 of the NetScaler Integrity Baseline; snapshot and collector follow in their own repositories (see Related repositories). Read the acceptance protocol before the first run on any new appliance. Version history: `CHANGELOG.md`.

## Why this and not a grep

### What it finds

- **Find the sleeper.** The sprayer that tries four accounts on Monday, pauses, and comes back Friday stays under every lockout and rate threshold. The cumulative address list sees the return; the report calls it what it is.
- **Find the spraying.** Dozens of machines, a thousand account names, one attempt each: grouped by /24, with rate, accounts and the question that matters, whether any of them got in.
- **Find the one account under fire.** Brute force on a single name is a different attack with a different answer. It gets its own finding, its own "call this person".
- **Find the hit.** A successful login after a failure series is red, with account, address and the three commands to run first.
- **Find the probe before the shell.** Requests for known webshell names in every theme folder, with the real source from the access log, and a red line if a webshell path ever answered 200.
- **Find the gap.** Missing logs, missing rules, unreadable files: the verdict says `INVESTIGATE` and names what it could not check. It never says `OK` for lack of evidence.
- **Compare running, saved and previous config.** Unsaved changes on the appliance are a finding; so is a security-relevant difference between `ns.conf` and `ns.conf.0` (new system users, policies, listeners, management access). An attacker who edits the running config without saving leaves no file for the next backup to catch; this check sees it.

### How it works

- **Decide, don't scroll.** One run, one verdict, "what to do" under every finding, on the appliance, in the FreeBSD shell, offline if it has to be.
- **Touch nothing.** No network connection, no change to configuration or system files, no agent, no Python. The script reads with the CLI layer on a read-only service user and writes only to its own directories. It runs during an incident without becoming part of it.
- **Compare with yesterday.** Point it at a snapshot set and it runs offline, on a box that may already be reimaged; with `--compare` it tells you what changed since the last snapshot: web files, cron, listeners, config. The daily cron run plus the snapshot make a time series, and the cumulative address list adds the "known since" to every attacker.
- **Mitigation that actually fires.** A responder policy against CVE-2026-88771 is only worth something if it is bound to the right vServers and its hit counter moves. The script checks the binding, reads the counters, and reports hits since the last run as an attack trace of its own.
- **Read-only by construction.** The CLI layer runs under a service user limited to `show` and `stat` by a command policy, with no `show techsupport` and no `show system file`; a 32-character secret in a 600-file, no password in any script or report. If you cannot grant that, the script runs without the layer and says what it could not see.
- **Keep your context.** Block list makes covered findings orange, whitelist removes confirmed changes, your own indicators live in a custom file that survives every update.
- **Own fix builds, own call.** Your custom file can carry CVE rows of its own: a hotfix build Citrix gave you, a train the public rules file does not list yet. Both files are evaluated, the stricter result wins, and a divergence between them is a finding, not a silent override.
- **Feed the firewall, then check it held.** Every run writes the foreign addresses it saw, by category (download host, dropper requester, probe source, spraying machine, sleeper, hit), into a per-run list and a cumulative list per appliance: first seen, last seen, days seen, count per window. What you block goes into `ns_quickcheck.blocked_ips` with its date; the next run marks covered findings orange and reports "block not effective" for any address that still gets through.
- **Hand it over.** Anonymized copies with a stable per-appliance mapping; account and host names masked, attacker values kept, address lists by category for firewall and SOC.
- **Two prompts, one rules file.** The repository ships the two prompts the rules are made with: a research prompt that collects a bulletin's facts from primary publishers only, with URL and date per value, and a rules prompt that turns that research into a patch in the rules-file format. Anyone can run them against the next bulletin or against their own findings, apply the patch with `rules-apply.sh`, and get the same lint, provenance and duplicate check we use. The method is in the repo, not only the result.
- **Trust the rules.** Every indicator traced to its first publisher, every release through 69 test logs, 10 fixtures and three platform lints; every threshold documented and configurable.

## What it checks

One run, six blocks, one verdict (`OK`, `UPDATE`, `INVESTIGATE`, `FORENSICS_FIRST`):

- **Build** against every CVE line of the rules file (fix builds per train, conditions such as SAML or `tcpParam`), end-of-life trains, unsaved config.
- **Exposure and mitigation**: SAML, DTLS, management access on SNIPs, responder policies and their hit counters.
- **Attack traces** from the appliance logs: injection attempts in logon lines with download host and source (also from responder lines), nsaaad crashes, dropper requests, webshell probing and webshells that answered, interpreter errors, management-plane and SSH access from outside, and account attacks on the gateway: password spraying, brute force on single accounts, slow "sleepers", internal addresses failing logins, and successful logins after a failure series (red).
- **Compromise quick check**: payload paths and webshell names from the rules and the operator's custom file, modified web files outside upgrade windows, cron, listeners, system users, suspicious processes, active connections to attacker addresses.
- **Operator context**: a block list (addresses already blocked at the firewall) turns covered findings orange, a whitelist removes confirmed changes, thresholds for the account checks live in a config file.
- **Outputs**: report, JSON, per-run and cumulative address lists by category, and anonymized copies that can leave the house. `coverage=partial` in the result line means a core check had no data; the verdict is then never `OK`.

Test basis: 69 test logs, 10 fixtures and three platform lints run before every release (`docs/release.sh`). Details: `ns_quickcheck_README.md` (German), sections 4.3 (thresholds) and 6 (blocks).

## Quick start

Download: the two files for an appliance, `ns_quickcheck.sh` and `ns_quickcheck.rules`, are attached to every release at https://github.com/ceterion/netscaler-quickcheck/releases; the repository itself is needed only for `--testlog`, the fixtures and rule maintenance.

```sh
# Appliance, as root. Upload via SCP in binary mode.
mkdir -p /var/nssnapshot && cd /var/nssnapshot
cp ns_quickcheck.conf.example ns_quickcheck.conf; cp ns_quickcheck.whitelist.example ns_quickcheck.whitelist   # first install only
chown root:wheel ns_quickcheck* && chmod 700 ns_quickcheck.sh && chmod 600 ns_quickcheck.conf ns_quickcheck.rules ns_quickcheck.whitelist
sh ns_quickcheck.sh                 # full output on screen, report and JSON under /var/nssnapshot/quickcheck/
echo EXIT=$?                        # 0 OK, 1 INVESTIGATE, 2 UPDATE or FORENSICS_FIRST, 3 aborted (reason on stderr)
```

Read the last lines first: `ACTION:` and the `RESULT` line. Exit 1 or 2 is a verdict, not an error; what to do is under every finding. Only if the run aborts without a `RESULT` line, repeat it with a trace (`sh -x ns_quickcheck.sh --no-out 2>/tmp/qc_trace.txt >/tmp/qc_out.txt`) and send both files, anonymized with `--anon`, to the contact address.

Before the first acceptance, on a workstation: `sh ./ns_quickcheck.sh --from ./docs/testdata/fixtures/compromised --hours 100000 --no-out` must end with `ACTION: FORENSICS_FIRST`, `fixtures/clean` with `ACTION: OK`; `sh ./ns_quickcheck.sh --testlog ./docs/testlogs/` must report 0 FAIL.

Options (each value option also as `--option=value`; a missing value aborts with exit 3):

| Option | Value | Effect |
|---|---|---|
| `--hours` | hours | log window, files changed within the last n hours (default 144) |
| `--from` | path | offline run against an unpacked snapshot set |
| `--compare` | `cron`, `latest` or path | compare against the latest complete set, the latest set, or an unpacked archive 1 |
| `--rules` | path | rules file; `ns_quickcheck.rules.custom` is looked up next to it |
| `--whitelist` | path | per-appliance whitelist |
| `--conf` | path | configuration file, loaded before all other options |
| `--out` | path | report file; JSON, address list and anonymised versions next to it |
| `--no-out` | | screen only, no files |
| `--anon` | file | anonymise any log excerpt with this appliance's mapping table, output on stdout, nothing else |
| `--full`, `--brief` | | everything on screen (default) or findings only |
| `--no-cli` | | skip the CLI level |
| `--testlog` | folder or file | check rule patterns against test logs (workstation, never appliance) |
| `--ki-bundle` | | anonymised material for rule maintenance (acceptance runs only) |
| `--version` | | print the version |

Acceptance on a new appliance: read every red and yellow line, classify each as stock state of the build, operator configuration or finding; stock states go into `ns_quickcheck.rules` (with source line and changelog), operator configuration into `ns_quickcheck.whitelist`; run again. Details: `ns_quickcheck_README.md`, section 7a. Expect two to five rule or whitelist entries per appliance type on the first run.

## Files

**Update of an installed appliance:** copy only `ns_quickcheck.sh` and `ns_quickcheck.rules`. `ns_quickcheck.conf` and `ns_quickcheck.whitelist` belong to the operator and are never part of an update; the repository ships them as `.example` so that a careless `cp *` cannot overwrite them.

All files carry unversioned names; the version of the script is in its header and in the `RESULT` line, the version of README and prompts in their first lines. Release notes are the only versioned files (`docs/release-notes_v<version>.md`).

| File | Purpose |
|---|---|
| `ns_quickcheck.trusted_ips.example` | template for the trusted list: addresses whose attack-like behaviour is wanted (scanners, pentests with an expiry date); reported as `[TRUST]`, effect findings stay red |
| `ns_quickcheck.blocked_ips.example` | template for the operator's block list (addresses already blocked at firewall, blocklist or appliance); findings for blocked addresses before the block date become ORANGE "covered", requests after the block date YELLOW "block not effective" |
| `ns_quickcheck.rules.custom.example` | template for the operator's own indicators (same format as the IOC section); copy to `ns_quickcheck.rules.custom` next to the rules file, loaded additively, never shipped or replaced on update |
| `<BASE_DIR>/tmp/` | working directory for intermediate files and `--compare` extraction (configurable `WORK_BASE`); never `/tmp`, which sits on the small root file system of a NetScaler |
| `ns_quickcheck_observed_ips.tsv` | cumulative list of observed foreign addresses per appliance, updated on every run; `grep -v '^#' ns_quickcheck_observed_ips.tsv | cut -f2 | sort -u` gives the plain address list |
| `ns_quickcheck_<host>_<time>_ips.tsv` | observed foreign addresses of the run by category (payload download host, injection source, dropper requester, outbound hit) with counts, for firewall block lists after review; also in the JSON as `observed_ips` |
| `ns_quickcheck.anon.<host>.map` | per-appliance mapping table for the anonymised reports (`_anon.txt`, `_anon.json`, written on every run); stays on the appliance, never shipped. `--anon <file>` anonymises any log excerpt with the same table |
| `ns_quickcheck.rules.provenance.md` | provenance log generated from the rules file: source, publication date and reference URL for every value |
| `ns_quickcheck.conf.example` | template for the optional configuration (window, report directory, CLI layer); copy to `ns_quickcheck.conf` on the appliance once |
| `ns_quickcheck.rules` | CVE table, attack patterns, payload paths, attacker addresses, stock states per build; one file for all operators |
| `ns_quickcheck.rules.changelog.md` | every rule change with bulletin reference, quote, test and distribution |
| `ns_quickcheck.whitelist.example` | template for per-appliance exceptions (accounts, listeners, paths, cron, theme files, own mitigation policies); copy to `ns_quickcheck.whitelist` once |
| `ns_quickcheck_README.md` | full documentation and runbook (German) |
| `ns_quickcheck_rules_prompt.md` | prompt for AI-assisted rule maintenance: fetches and extracts the bulletin, outputs a patch for `docs/rules-apply.sh`; bundle input only as a special case |
| `ns_quickcheck_research_prompt.md` | prompt for a separate research chat: bulletins, indicators, Sigma and YARA rule diffs, VirusTotal lookups, community tool diffs, false positives |
| `docs/rules-prefix-check.sh` | verifies that a rule update only appended |
| `docs/rules-apply.sh` | applies an AI-produced rule patch additively and runs syntax, prefix and test-log checks |
| `WORKFLOW.md`, `WORKFLOW.de.md` | seven-step operator workflow from bulletin to distributed rule file (English, German) |
| `docs/release.sh` | refreshes `ns_quickcheck.sh` from the versioned script and checks they match |
| `docs/PLATFORM.de.md` | platform findings: NetScaler `/bin/sh` crash on `$( { ...; } | ... )`, stock listeners, aliases, log formats |
| `docs/releases/` | release notes per version (`v17.30.md`) and per rules stand (`rules-<date>.md`); the text of the GitHub release |
| `docs/testdata/` | rule file states for the prompt acceptance test and prefix check; `fixtures/clean` and `fixtures/compromised` for a full offline run with expected verdicts (`fixture-expected.txt`), never copy to an appliance |
| `SECURITY.md`, `.github/ISSUE_TEMPLATE/` | reporting rules and issue templates for false positives and missed indicators |
| `docs/testlogs/` | test logs per CVE plus `clean.log`, `admin-audit.log`, `expected.txt`, `herkunft.md`; run with `--testlog`, never copy to an appliance |

## Related repositories

| Repository | Function | Status | Roadmap | Interface to quickcheck |
|---|---|---|---|---|
| `netscaler-snapshot` (separate repository, to follow) | daily file-level snapshot per appliance: four archives, manifest with timestamps and SHA-256, state of processes, listeners, cron and running config via a read-only service user, normalised diff of running vs. saved config | V7, lab-validated on 14.1-73.41 | pull transport from the collector, quickcheck report directory in archive 1, blocklist mode on demand | `--from` and `--compare` read extracted sets; `CLI_USER` and secret are taken from `ns_snapshot.conf` |
| `netscaler-collector` (separate repository, to follow) | PowerShell 7 collector: verify sets, import idempotently, daily diff with classification and filters, report as traffic light, IoC rescan over 90 days | V2, step 1 of 3 (import), tested with synthetic sets | step 2 compare, step 3 report and alerting, encryption at rest, pull transport | reads `quickcheck/*.json` as a traffic-light input once the snapshot ships the directory |

The quickcheck runs without either: without the snapshot it uses its own `ns_quickcheck.conf` and, without a service user, the saved configuration (option A). The optional CLI layer and the service user are described in `ns_quickcheck_README.md`, section 3.1.

## Known limits

- Pattern-based. `OK` means: fixed build, no known indicator matched, no traces in the window. **It does not mean the appliance is clean**; an attacker using paths or names nobody has published yet stays invisible to any rules-based check. If the appliance was exposed before the fix, run the vendor's IoC scan as an independent second opinion: the "Indicators of Compromise" function of NetScaler Console (https://docs.netscaler.com/en-us/netscaler-console-service/instance-advisory/ioc), or the scanner from Citrix Support via a ticket if no Console is in use.
- Report and finding texts are German in this release, by design (see the language note at the top); field names, verdicts and the result line are language-neutral (`docs/report-format.md`). An English output option (`--language en`) is planned for V18.
- Stock states differ per build family. On 13.1 or FIPS expect false positives on the first run until `KNOWN_LISTENER_RE`, `STOCK_ALIAS_ROOTS` and `ADMIN_CMD_RE` are extended.
- NetScaler's `/bin/sh` crashes on any brace group inside a command substitution, e.g. `$( { ...; } | ... )` or `$(a | { ...; } | b)`. Do not add that construct; `docs/release.sh` lints for it.
- Source-IP correlation and policy hit deltas are untested against real logon volumes.
- The process check for `ns_monuploadd_err.pl -WR` (CISA SIGMA S7): on 14.1-73.46 the script is started by the daemon `/netscaler/monuploadd`, not by cron; that parent is reported as info, cron as yellow, anything else as red. Other builds not verified.
- For CVE-2026-107406 (CTX697191) no public indicators exist as of 2026-10-14; the rules only carry its preconditions and fix builds.
- The test logs under `docs/testlogs/` are largely constructed from published patterns (see `herkunft.md`); they verify the regexes, not real-world coverage, until replaced by reported or lab-generated lines.

## Contributing

Author and maintainer: Jens Miltenberger, ceterion AG, working with Citrix appliances since 2004, from the Net6 Access Gateway through Citrix's acquisition of NetScaler to today's ADC and Gateway builds. See CREDITS.md.


Contact: netscaler-integrity@ceterion.com for questions and acceptance support; security defects in the script go to security@ceterion.com (see `SECURITY.md`), never into a public issue.

Issues and pull requests welcome. Rule changes must be additive, carry a source line (`# +<date> <source>: <what>`) and a changelog entry. Source rule by impact: build numbers and CVE rows only from the Citrix bulletin; log patterns only from sources that show the observed line, tested against real logs; paths, hashes, addresses and domains also from secondary sources, marked as such. Every new log pattern comes with a test line in `docs/testlogs/` and an expectation in `expected.txt`; `sh ns_quickcheck.sh --testlog docs/testlogs/` must pass. Shell changes must be POSIX sh and tested on a NetScaler. By contributing you agree to the Apache License 2.0 terms for your contribution (section 5).

## Credits

Indicator data comes from the original publishers named per line in the rules file (Citrix, CISA, CERT-EU, Unit 42, LevelBlue, watchTowr, SOCRadar and others). See [CREDITS.md](CREDITS.md).

## License

Apache License 2.0, see `LICENSE` and `NOTICE`. Provided "AS IS", without warranty of any kind; see `DISCLAIMER.md` (German and English). A verdict of this tool does not replace a forensic investigation or a vendor statement.

Copyright 2026 ceterion AG.
