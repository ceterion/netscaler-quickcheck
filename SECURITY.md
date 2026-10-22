# Security Policy

## Scope

This repository contains a triage script for Citrix NetScaler appliances and a rules file with publicly documented indicators. The script reads configuration, logs, file system, processes and listeners; it does not change appliance configuration or system files, does not open network connections and does not transmit data. It writes only to its own directories: reports, JSON, address lists and anonymized copies to `/var/nssnapshot/quickcheck/`, a per-appliance mapping table next to the rules file, and temporary files to a work directory under `/var/nssnapshot/tmp` (or `WORK_BASE`), removed after the run. Nothing is written to `/nsconfig`, `/flash` or the web directories.

## Reporting

**Missed indicators or false positives** are not security vulnerabilities of this project. Open a public issue using the "Fehlalarm / False positive" or "Übersehener Indikator / Missed indicator" template; include build, anonymised line and rule version. Without a GitHub account: netscaler-integrity@ceterion.com.

**Security defects in the script itself** (for example: a code path that modifies the appliance, writes secrets to a report, follows attacker-controlled input, or crashes the appliance shell) should not be reported publicly. Send them to security@ceterion.com with the script version (`VERSION` line in the header), the rule version and a reproduction, ideally against the fixtures in `docs/testdata/fixtures/`.

You will get an acknowledgement within five working days. Fixes are released as a new script version with a changelog entry; the reporter is credited in CHANGELOG.md unless they ask otherwise.

## What to attach

For any report, the anonymised report (`_anon.txt`, `_anon.json`) is sufficient; never attach the original report, the mapping table or the custom file. Log excerpts go through `sh ns_quickcheck.sh --anon <file>` first.

## Supported versions

Only the latest tagged script version and the latest rule file are maintained. Rule files are additive; an older rule file is never wrong, only incomplete.

## Please do not

Do not upload customer reports, logs or `--ki-bundle` output to this repository. Anonymise first; the project cannot delete data from the Git history of forks.
