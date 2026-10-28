# Changelog

English summary. The German version [CHANGELOG.de.md](CHANGELOG.de.md) is leading and carries the full detail per version; this file is brought in line at the latest with each release. Full release notes per release: `docs/releases/` (also the text of the GitHub release). The rule changelog `ns_quickcheck.rules.changelog.md` is kept in German only.

## Planned (V18)

- Stock manifest per build (hashes of all web and management files from a fresh installation; block 5 distinguishes stock file, modified stock file and new file; solves the whitelist maintenance problem)
- Address feed from operators' share files (collector: dedupe, two-appliance rule, expiry, abuse process)
- `WEBSHELL_NAME_RE`: webshell names as patterns across the web directories instead of exact paths; trigger Zscaler 16.10. (`Nx_<number>.php/.pl/.html`, number differs per attack instance)
- "New since last run": findings unchanged for n runs marked as known; only new findings on top
- `--language en` with message catalogue; English main documentation
- Shell logs (`bash.log`, `sh.log`) with `SHELL_CMD_RE`, only with a whitelist built from real lines
- `--compare` with hash diff instead of mtime, cron and `httpd.conf` included in the comparison
- Stock lists and stock hashes for 13.1 and FIPS

## v17.43 (2026-10-28)

Empty boot cores (INFO) no longer count as core evidence; no yellow block without an event.

## v17.42 (2026-10-28)

Cores: compressed files assigned to their event; directory cores `/var/core/<n>` that are empty and shortly after boot reported as INFO (`CORE_BOOT_LEVEL`), otherwise yellow; verdict sentence on mitigation only with an open CVE; rules 2026-10-28e with stock hash for 73.49. Freeze.

## v17.41 (2026-10-28)

Crashes: every event at least yellow; red for nsaaad with SAML from the second event per day, httpd with open PHP2Shell, nsppe with DTLS, three events of one process per day, the same process on three days (`ns_quickcheck_observed_crashes.tsv`), or an external request in the 120 s before (`crash_trigger`). New evidence: Apache worker crashes (`HTTPERR_CRASH_RE`), core without log line, kernel panic (`KERNEL_PANIC_RE`), memory pressure (`KERNEL_MEM_RE`), reboot without command. `crashes=` in RESULT. Rules 2026-10-28d.

## v17.40 (2026-10-28)

Pitboss process lines (`proc <name> (<pid>) SIGNALED` / `EXITED with status 0x8b`) attached to the event, signal derived from the exit status; event times taken consistently from the syslog header (local time). Rules 2026-10-28c.

## v17.39 (2026-10-28)

Process crashes: restart counter per event, core evidence as files `/var/core/<proc>-<pid>` and as directories, attached per event; rules 2026-10-28b with three more pitboss and kernel line types from the lab.

## v17.38 (2026-10-28)

Verdict names open CVEs, bulletins and target build; `vuln96` now covers CTX697096 only, new field `vuln_open`; logon summary with account per source; anonymisation masks host names from URLs and NT/DNS domains from config values.

## v17.37 (2026-10-28)

CVE table: fix build `pending` (no fix build published, every build of the train vulnerable); `rules-apply.sh` 2.5, format 2 version 1.4. Research prompt v17, rule prompt v8. Minor fixes in test logs, `docs/testdata/README.md`, runbook step 7 and `release.sh`.

## v17.36 (2026-10-27)

Rules 2026-10-28: fix builds for PHP2Shell (CTX697263, update of 27.10.) corrected to 14.1-73.49, 13.1-64.32, 14.1-FIPS 73.49, 13.1-FIPS 37.286. Rules 2026-10-23 and 2026-10-27 carried the fix builds of the SAML bulletin and wrongly reported appliances on 73.41 to 73.46 as fixed. Web file timestamps via perl, platform lint 4 against GNU awk functions; directory rules in the whitelist discouraged.

## v17.35 (2026-10-27)

`--pin-all <path>` (pin lines for all files, not only code); WORKFLOW in both languages with a section on whitelist entries with a hash per file.

## v17.34 (2026-10-27)

Whitelist with three rule forms (directory `/`, file `$`, file with pin `$@sha256=`); directory rules never cover code, file rules on code only with a pin. `--pin <path>` generates pin lines. Web files listed with modification time, grouped from 20 per directory. README section 15 whitelist howto as five steps, new template.

## v17.33 (2026-10-27)

Anonymiser: accounts shorter than 3 characters and reserved report words no longer enter the mapping table (an account `info` had turned `[INFO]` into `[userNNN]`). Web files classified across all changed files; executables never classed as theme customisation. Whitelist hash pin, probing time span in chronological order, fixture `aaa-dup`.

## v17.32 (2026-10-27)

Self-hits removed: `nsprofmon_mgmt.pl` lines (CPU snapshots containing the quickcheck's own grep and perl command lines) are checked only against `SUSPECT_PROC_RE`; identical lines from `ns.log` and `messages` count once, so block 4 shows fewer hits than 17.31. Process crashes as events per process and PID; anonymised address lists and share file `_share.tsv` for submission to ceterion. Rules 2026-10-27.

## v17.31 (2026-10-27)

Trust list `ns_quickcheck.trusted_ips` (`--trusted`): trusted addresses count as internal for management, SSH and logon failures and appear as blue `[TRUST]` without verdict effect; impact findings stay red. Footer with tool, version, rules and source (`FOOTER=1` default), `source_url` in JSON. Fixture `trusted`.

## v17.30 (2026-10-23)

CTX697263 (PHP2Shell, CVE-2026-109618 and 109619 in the management portal), rules 2026-10-23. Script: `vuln63` in RESULT; block 2 shows management addresses and the Citrix mitigation (DENY ACLs on ports 80/443, `MGMT_ACL_RE`); block 4b checks PHP memory and fatal patterns also in `admin_ui` (`HTTPERR_PHP_ANOMALY_RE`, threshold `PHP_ANOMALY_MIN`): INFO on a fixed build, yellow on a vulnerable one, red with a new PHP file in the window (block 5). Heuristic, no published signature. Test log `httperror-php.log`, fixture `php2shell`. Existing checks unchanged.

## v17.29 (2026-10-21)

First release after the withdrawn v15.1; rules 2026-10-22b. The individual steps 17.0 to 17.29 are listed in the script header, the release notes in `docs/releases/`.

**Rule file and provenance**
- Rule file format 2: every indicator line carries source, publication date, location at the original author and rules state; lines without a location are inactive. Binding description `docs/rules-format-2.md`, lint in `rules-apply.sh` and `release.sh`
- Provenance log `ns_quickcheck.rules.provenance.csv/.md`, generated from the rule file at every release
- Rules 2026-10-20: attested values only (111 indicators, 40 CVE rows); third-party compilations count as a reference, not as a source
- Values from third-party blocks of a community checker removed (see rule changelog 2026-10-19); new `CREDITS.md`, README section Credits

**Operator custom file**
- `ns_quickcheck.rules.custom` next to the rule file, loaded additively, never distributed, kept on update; IOC block and CVE block; identical lines count once, differing lines both, the stricter result applies; header line and RESULT (`custom`, `custom_sha256`, `cve_custom`, `cve_conflict`)
- `docs/rules-apply.sh` 2.3: `<target> <patch>` backs up as `<target>.bak_<state>` and updates in place; duplicates, locations and CVE rows checked; notice on deviation from the rule file
- WORKFLOW in both languages rewritten: the operator maintains indicators and fix builds in the custom file

**Reports, anonymisation, addresses**
- The terminal shows everything that goes into the report; `--brief` for the short version
- Anonymised version per run (`_anon.txt`, `_anon.json`, file name with substitute host) based on the mapping table `ns_quickcheck.anon.<host>.map`: addresses, hosts, users, domains, object names, themes; `--anon <file>` for log extracts
- 17.12: `--anon` also for `ns.conf`: secrets behind secret parameters, password hashes and SNMP communities become `***` without a table entry; FQDNs, certificate files, DN components and server names go into the mapping table; comment lines reduced
- Address list per run (`_ips.tsv`, `observed_ips` in JSON) and cumulative per appliance (`ns_quickcheck_observed_ips.tsv`)
- JSON per finding `text` and `details`, `mitigation_hits`
- Explanation lines per finding; 17.17: finding blocks with fixed labels (when, result, download host or address with block list, rule file and address list, source, to do) for injection, dropper requests and web files; before RESULT the addresses of this run with status against the inventory and the block list; source shown on a payload path hit

**Assessment**
- 17.16: block list in the format `address ; since ; remark`, finding text "blocked from DATE", remark only in the original report; date routine in perl (BWK awk has no intervals, platform lint 3), an undeterminable date reads "coverage not verifiable"
- 17.15: block list accepts lines with two or more fields (where as free text, date optional), reports skipped lines; fix: comment reduction of the ns.conf anonymisation deleted the header line of the anon reports
- 17.13: operator block list `ns_quickcheck.blocked_ips` plus ACLs of the appliance; findings for blocked addresses before the block date become ORANGE "covered" instead of red, requests after the block date YELLOW "block not effective", active connections stay red; address lists with a blocked column, RESULT `orange=` and `blocked_seen=`, JSON list `orange`; fixture `blocked`
- 17.11: dropper block detects dropper searches (more than two different package names from one address, or command characters in the query string) and reports red instead of yellow; detail lists complete in terminal and report, `DETAIL_MAX` in the config limits them if needed
- Verdict vocabulary `OK`, `UPDATE`, `INVESTIGATE`, `FORENSICS_FIRST`
- Fix: SAML-dependent CVE (CVE-2026-107406) did not set `vuln79`; fix: `EOL_RELEASES` was never evaluated; fix: IP indicators matched as substrings; `OUTRE` with boundaries

**Operation**
- Fix 17.10: BSD sed does not know `\t`; the cumulative address list stayed empty on the appliance, "vulnerable" lines were missing in JSON. Switched to awk and printf, platform lint 2 against it
- Working directory `$BASE_DIR/tmp` instead of `/tmp` (the root file system ran full with `--compare`), space check, configurable `WORK_BASE`
- Options that take a value abort with exit 3 when the value is missing
- Fixture gate checks RESULT fields; fixtures `eol` and `custom`; test logs in the real httpaccess format and a negative test

**Documentation**
- README rewritten (quick start, verdict decision table, options, security considerations, FAQ, glossary); unversioned file names in the repository, versions in the file header; rule changelog starts with the first published rules state

## v15.1 (2026-10-19, release withdrawn; reason see rule changelog, entry 2026-10-19)

First public release. Script V15.1 (validated on 14.1-73.41 and 14.1-73.46), rules 2026-10-16b.

- 15.1: httpd.conf with an mtime away from boot time is red only if its content has a finding (alias into gateway paths, PHP handler or flags); otherwise yellow with a hint to installation or upgrade. False positive in the acceptance run on 19.10. on the fresh 14.1-73.46 from 14.10.: `installns` had written httpd.conf at 10:38, the file is not regenerated at every boot, the content was clean, the verdict was nevertheless FORENSICS_FIRST
- Rule file: all eight CVEs from CTX697096 with conditions in the bulletin wording, CTX697174, CTX697191; 153 addresses, 19 domains, 38 hashes, payload paths from Unit 42, CERT-EU, LevelBlue, watchTowr, SOCRadar, a community checker (MIT, no longer used since 2026-10-19) and cisagov/SIGMA_Rules 261399 r1; prepared variables `SCANNER_IP_RE` and `PAYLOAD_HASHES` for V16
- Tests: `docs/release.sh` with platform lint, 29 test log expectations, two fixtures (clean, compromised); provenance per test line in `docs/testlogs/herkunft.md`
- Known gaps (V16): `--anon`, `HTTPD_SUSPECT_RE`, `BACKDOOR_USER_RE` (`sec_monitor` still hard-coded in the script), evaluation of `SCANNER_IP_RE` and `PAYLOAD_HASHES`, port ranges for listeners, content check of web files; snapshot and collector follow as separate repositories

## 2026-10-16 - rules 2026-10-16 to 2026-10-16b, research prompt v11 to v13, release package

- Rules 2026-10-16: payload paths `ns_helper`, `.ns_helper`, `/tmp/.p` (Huntback, via community)
- Rules 2026-10-16b: cisagov/SIGMA_Rules republished the rule on 13.10. as 261399 r1 (modified 2026-10-07); 209 keywords compared, new: 4 hashes, 7 paths, dropper `nsgtrust.deb`
- Research prompt v11 to v13 (guards against invented fetches, fork pinned to a commit, KEV fallback, updated Sigma URL, status list, sort check against dateReleased); frozen after v13, acceptance per step 5a2
- Validation log in the prompt document: runs with Claude Opus (v2 to v7), ChatGPT (v8, v9), ChatGPT Astra (v10), Gemini (v10, entirely fabricated), incognito reviews
- `docs/git-init.sh` removed; `docs/release-notes_v15.0.md`; changelog gap text for the appliance run on 20.10.

## 2026-10-15 - rules 2026-10-15 to 2026-10-15e, research prompt v5 to v10, rules-apply 1.2, community diff

- Rules 2026-10-15 to 15e: Unit 42 addresses and dropper names; CERT-EU, LevelBlue, watchTowr, SOCRadar post-exploitation paths, C2, listener `walk`; CVE-2026-88773 to 88777 as table rows with bulletin conditions; community checker read directly (MIT, no longer used since 2026-10-19); conditions of 88774, 88776 and 88777 corrected to the wording of CTX697096
- First attested log line in the test set (CERT-EU), test log expectations at 29
- Research prompt v5 to v10 (mandatory URLs, fetch evidence, fetched content treated as data, KEV via cisagov/kev-data, two model roles)
- `NOTICE`: community checker as source of the lists with licence and copyright (no longer used since 2026-10-19)
- WORKFLOW step 6b (new community version; dropped since v15)

## 2026-10-14 - operator workflow

- `WORKFLOW.de.md` / `WORKFLOW.md`: seven-step operator workflow from a new bulletin to a distributed rule file, written for admins without repository experience.
- `docs/rules-apply.sh`: applies an AI-produced patch additively (append only, unknown variables rejected) and runs syntax, prefix and test-log checks; `rules-prefix-check.sh` now prints a success line and a help pointer.
- Rule prompt v7: phase 0 fetches and extracts the bulletin into a table with quotes, output B is a patch for `rules-apply.sh`, at most three questions with defaults, bundle input only as a special case with the data-protection rule. README v21.

## 2026-10-14 - docs

- Research prompt v3: SigmaHQ and signature-base rule diffs, VirusTotal hash lookups, field sources, impact-based source rule inside the prompt. README v20: VirusTotal lookup with upload prohibition in the runbook; "customer" replaced by "operator" throughout. Issue templates bilingual; contact links removed from config.yml (GitHub does not render mailto links).

## 2026-10-14 - v15.0

- `SECURITY.md`, issue templates (false positive, missed indicator) and contact addresses added; v15.0 validated on 14.1-73.46 (lab, online).
- v14.0 validated on 14.1-73.46 (lab, online and offline). Fix: the hash-match branch called an undefined output function (since 12.0, visible only on a build with a stock hash). `docs/release.sh` now lints output calls against defined functions.

## 2026-10-14 - v14.0, rules 2026-10-14b

- v13.0 validated on NetScaler 14.1-73.46 (fresh lab install): fixtures clean and compromised, online run, no crash.
- Lab finding: `ns_monuploadd_err.pl` is invoked by the daemon `/netscaler/monuploadd` (pitboss-watched), not by cron. v14.0 rates the parent in three tiers (daemon info, cron yellow, other red) and flags shell or downloader children of the script as red. Rules 2026-10-14b add `SUSPECT_PROC_PARENT_OK_RE`, `SUSPECT_PROC_CHILD_RE` and the first stock hash (`ns_monuploadd_err.pl`, 14.1-73.46).

## 2026-10-14 - v13.0

- `ns_quickcheck.conf` and `ns_quickcheck.whitelist` ship as `.example` templates so an update cannot overwrite operator files; update means script and rules only. Rule changelog carries the SHA-256 of 2026-10-14.
- Fix: SIGSEGV of the NetScaler shell in block 5 (brace group inside a command substitution in the system-user check, present since 10.0 and never run on an appliance). Lint added to `docs/release.sh`; platform rule extended. Found by running the fixtures on an appliance.

## 2026-10-14 - v12.0, rules 2026-10-14

- Fixtures `docs/testdata/fixtures/clean` and `compromised` with expected verdicts; `docs/release.sh` runs them after `--testlog`. README 4.1 lists an example per option with the standard path. Dropper-path check moved after injection detection so the red tier applies.
- Rules 2026-10-14 from the CISA SIGMA rule CMA_SIGMA_Citrix_CVE_2026_8871 (2026-09-29), Sygnia and Unit 42: `b64decode`, `INDEX:`, `c88771.json`, new `SUSPECT_PROC_RE`, `DROPPER_PATH_RE`, `STOCK_HASH_FILES`/`STOCK_FILE_HASHES`; note on the eight CVEs of CTX697096.
- v12.0: process check with parent (`cron` yellow, otherwise red), dropper-path requests per source IP (yellow, red with injection), system file hashes (info until a stock value exists). Principle: sensitivity over specificity, uncertain stock states reported yellow with reason.
- Test logs extended (CISA, Unit 42, Sygnia lines; name edge cases in `clean.log`; `admin-audit.log`), `--testlog` now covers `DROPPER_PATH_RE` and `SUSPECT_PROC_RE`: 29 PASS.
- Copyright notice unified to `Copyright 2026 ceterion AG`, author named in NOTICE; NOTICE lists indicator sources and states that no third-party code was used. Rule changelog carries SHA-256 for all archived states.

## 2026-10-13 - v11.0, rules 2026-10-09d

- `--testlog`: checks the rule file's log patterns against `docs/testlogs/` and `expected.txt` (PASS/FAIL, exit code). Mandatory before every rule change; `docs/release.sh` runs it.
- `docs/testlogs/`: one file per CVE, `clean.log` as false-positive test, `expected.txt`, `herkunft.md` with provenance per line (constructed lines marked, to be replaced by reported or lab lines).
- Prompts: research v2 asks for verbatim log lines with source; rules v6 requires a test line and an expectation per pattern.

Releases: tag `v<major>.<minor>` for the script, `rules-<date>` for the rule file (convention until 2026-10-19; since then script tags only, the rules state is recorded with SHA-256 in the rule changelog). Details per change in the script header and in `ns_quickcheck.rules.changelog.md`.

## 2026-10-09 - v10.0, rules 2026-10-09d (repository split, not published)

- `ns_quickcheck.sh` as unversioned copy of `ns_quickcheck_V10.sh` for operational use, kept in sync by `docs/release.sh`; rules 2026-10-09d allow the unversioned name in `ALLOWED_CRON_RE`. Documentation and prompts stay versioned only.
- Repository `netscaler-quickcheck` split out of the NetScaler Integrity Baseline; snapshot and collector follow separately.
- README v13: related repositories with function, status, roadmap and interfaces; optional CLI layer without snapshot; source rule for secondary indicators.
- Rules 2026-10-09c: provenance of community indicators marked as secondary source; 2026-10-09b: `72.5.65.111`, `v5v.in`; 2026-10-09: CTX697191 / CVE-2026-107406 with role-dependent fix builds (SP from 73.37/64.23, IdP from 73.46/64.29).
- Prompt v5 and README 7.1: source rule by impact of a wrong entry (bulletin only for builds and CVE rows; observed-line sources for log patterns; secondary sources allowed for paths, hashes, addresses, domains). Research prompt v1.
- `docs/rules-prefix-check.sh` replaces the earlier, incorrect prefix check command.

## 2026-10-08 - v10.0 (unreleased)

- 10.0: findings of an acceptance run on a production appliance: password hashes in the `ns.conf.0` diff masked, `CLI_USER` automatically allowed as service user, whitelist type `mitigation:`, `--compare cron`. Rules 2026-10-08e operator-neutral.
- 5.0 to 8.0 (lab, 14.1): NetScaler sh crash on `$( { ...; } | ... )` fixed; 14.1 stock states (PHP handler, listeners, aliases, shell audit, profiler lines) as rules instead of findings; burst rule for web files; alias check by target.
- 3.0 and 4.0: CVE table in the rule file, `ns.conf.0` diff, hit-counter deltas, script and rules hash, `--ki-bundle` with anonymisation and self-check.
- 2.0: config layering, report as text and JSON, whitelist, time-zone matching, `--compare`, outbound connections, HA peer hint.

## 2026-10-06 - 1.0

- First version: six blocks, online and offline mode, rule file, defanged output, RESULT line, verdict with action text.
