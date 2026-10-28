# Workflow: new indicators and new bulletins

Deutsch: [WORKFLOW.de.md](WORKFLOW.de.md)

For admins who run the Quickcheck without maintaining the repository. Target time 20 minutes.

## Two files, two responsibilities

| File | Maintained by | Contains | On update |
|---|---|---|---|
| `ns_quickcheck.rules` | ceterion | detection patterns, fix builds per CVE (`CVE_TABLE`), confirmed indicators with reference | replaced |
| `ns_quickcheck.rules.custom` | the operator | own indicators (IOC block) and own fix-build rows (CVE block): field findings, values and bulletins ceterion has not yet picked up | kept |

Both files are evaluated together. If a CVE is in both with a different fix build, the script evaluates both rows and shows both results; the stricter one decides. A custom row can therefore never make an appliance greener than the rules file, only stricter. What the operator cannot bring in through the custom file: new detection patterns (regex) and script changes; see step 7.

**Prerequisites, once**
- The repository unpacked or cloned on your workstation, a terminal with `sh`, `grep`, `awk`, `perl` (macOS, Linux, Windows with WSL). The folder holding `ns_quickcheck.rules`, `docs/` and your custom file is the "tool folder" below.
- Access to an appliance as `nsroot` via SSH and SCP, a lab or an HA partner first.
- An AI account (ChatGPT, Claude, Mistral or a company service). No operator data is transferred in this workflow, so any account will do.
- First time only: copy `ns_quickcheck.rules.custom.example` to `ns_quickcheck.rules.custom`; it is empty apart from the header.

## Short form

| # | Step | Command or input |
|---|---|---|
| 0 | Routine without a trigger only: research prompt, list of new bulletins and reports | `ns_quickcheck_research_prompt.md` |
| 1 | Rules prompt with the report or bulletin, the rules file and the custom file | `ns_quickcheck_rules_prompt.md`, blocks 0 and 1 |
| 2 | Check the output: a quote for every number, an original-publisher URL for every indicator | in the chat |
| 3 | Save the `# rules-patch` block from the chat as `ns_quickcheck.rules.patch` in the tool folder, then apply; the old custom file is backed up automatically | `sh docs/rules-apply.sh ns_quickcheck.rules.custom ns_quickcheck.rules.patch` |
| 4 | Read the checks: lint, syntax, notes; message "updated, backup: ..." | output of step 3 |
| 5 | Run on one appliance: custom file next to the rules file; header line "Custom-Datei des Betreibers geladen" | `sh ns_quickcheck.sh --no-out` |
| 6 | Custom file to all appliances, run, record `CUSTOM_VERSION` per device; leave `ns_quickcheck.rules` alone | `chmod 600`, root:wheel |
| 7 | Optional: submit confirmed rows as an issue so they enter the rules file | GitHub |

## Getting started

**Report or bulletin known** (Citrix security mail, CISA, vendor blog, colleague): continue at step 1.

**Routine without a trigger** (recommended every two days, daily for a week after a bulletin):
1. Open `ns_quickcheck_research_prompt.md`, copy the prompt block, paste it into an AI account.
2. Fill the parameters: cut-off date (date of your last request, the first time the date from `RULES_VERSION`), rules state, script version.
3. Read the result: "changes since" lists new bulletins and reports. None: done, note the date. One or more: step 1 for each.

Most common mistake: the chat names a source without a URL or a bulletin without a CTX number. Open every URL and every CTX number once in the browser before it goes into step 1.

## Step 1: rules prompt

Goal: the AI reads the bulletin or report for you and delivers the new rows as a patch.
1. Open `ns_quickcheck_rules_prompt.md`, copy the prompt block (between the ``` ), paste it into a new chat window; not into the research chat, separate roles.
2. Block 0: CTX number or URL. If the chat can fetch web pages it gets the text. Otherwise open it in the browser, copy the section with builds or indicators, paste it as block 0.
3. Block 1: the content of `ns_quickcheck.rules` (so the AI knows what is already covered) and below it the content of your `ns_quickcheck.rules.custom`.
4. Leave blocks 2 and 3 empty. Send. The AI asks up to three questions; answer "Standard" if the assumptions fit.

Expected: first the extraction table (builds, fix builds, condition, each with a quote) or the indicator table (original publisher, URL, date), then A to E, with patch block B containing `CVE_TABLE:` and `IOC:` lines.

Most common mistake: files pasted incompletely because the chat window cut them off. Check: the last line of the pasted block is `IOC` or `CVE`.

## Step 2: check the output

Goal: no number and no value without evidence.
1. Fix builds: next to every build number there is a quote from the bulletin; the quote must contain the number. If it is missing or says "not stated", do not take the number. The AI likes to "complete" numbers (73.46 becomes 73.47 because it sounds plausible).
2. Indicators: every `IOC:` line has six fields; the sixth is the URL of the original publisher (the rules stand is added as a seventh field when the patch is applied) (authority, vendor of the report, vendor blog). A compilation (community scanner, aggregator page) is not a reference; the AI must have marked such lines `PRUEFEN`, they stay inactive. Two spot checks: open the URL, search for the value on the page.
3. Do not take suggested log patterns (C); they belong to ceterion (issue, step 7).

## Step 3: apply the patch

Goal: your custom file plus the new rows; nothing edited by hand.
1. Save patch block B as `ns_quickcheck.rules.patch` in the tool folder (text editor, not Word). First line `# rules-patch 1  <source>  <date>`.
2. In the terminal, in the tool folder: `sh docs/rules-apply.sh ns_quickcheck.rules.custom ns_quickcheck.rules.patch`
3. The script backs up your custom file as `ns_quickcheck.rules.custom.bak_<old state>`, checks every new row (format, reference, no duplicate), sets `CUSTOM_VERSION` and writes the file. If a check fails, the file stays unchanged. If the rules file rates the same CVE differently, the script says so ("both are checked, the stricter result decides").

Expected: `== Format-2-Lint ok`, `== Syntax ok`, then "ns_quickcheck.rules.custom aktualisiert, Sicherung: ...", `CUSTOM_VERSION` and hash.

Most common mistake: `ERROR Format 2: IOC-Zeile ohne 6 Felder oder Fundstelle`: the AI left out a reference. Add or drop the line, run again.

## Step 4: understand the checks

- **Format-2 lint**: only permitted lines, a reference per indicator, valid CVE rows, no duplicates, no shell constructs. Described in `docs/rules-format-2.md`.
- **Syntax**: `sh -n`; the file must load.
- Test logs and fixtures do not run for the custom file; they test the patterns of the rules file, which you do not change. Your test is the run on the appliance.

## Step 5: run on one appliance

Goal: see the new custom file in a real run before it is everywhere.
1. Upload via SCP (WinSCP: binary mode) to `/var/nssnapshot/ns_quickcheck.rules.custom` on a lab or HA appliance. Permissions: `chown root:wheel`, `chmod 600`.
2. Run: `sh /var/nssnapshot/ns_quickcheck.sh --no-out`
3. Header: `[INFO] Custom-Datei des Betreibers geladen: <n> aktive Indikator-Zeile(n), <m> CVE-Zeile(n) (<CUSTOM_VERSION>)`. If missing: check file name, folder or permissions. With differing fix builds a second INFO line follows with both values.
4. Block 1: custom rows are marked `[custom]`. Compare the verdict with the last run; a new red from a custom row is the expected result when the build is below the new fix.

Most common mistake: file with Windows line endings; on the appliance `tr -d '\r' < ns_quickcheck.rules.custom > x && mv x ns_quickcheck.rules.custom`, set permissions again.

## Step 6: deploy

1. The same file to every appliance under `/var/nssnapshot/`, permissions as above. Leave `ns_quickcheck.rules`, `.conf`, `.whitelist` and `.anon.map` alone.
2. Run per appliance; record `CUSTOM_VERSION` and `custom_sha256` from the `RESULT` line in your own device list (for example `hosts.md` in the operator folder) of your operator folder.

## Step 7: back to the repository (optional)

Rows with a quote or an original-publisher URL can be submitted as an issue "Indicator" or "New bulletin"; ceterion checks them and takes them into the next rules state. Afterwards you have the row twice (rules file and custom); identical rows are evaluated once, which is harmless. Values only you may use and field findings never go into an issue. Log pattern suggestions also go into an issue, never into the custom file.

## Account findings

Block 4 reports attacks on gateway accounts in a fixed order; the response per finding:

| Finding | Response | When |
|---|---|---|
| Hit (red) | lock the account, reset the password, `kill aaa session -userName <account>`, then ask the user whether it was them | now |
| Brute force on one account | check account and owner (MFA, how the name became known), addresses into the block list, consider lockout (README 15, Howto Lockout) | today |
| Machines and networks, sleepers | block the networks at the firewall and record them in `ns_quickcheck.blocked_ips`; the next run shows "block not effective" if not | with the next firewall change |
| unclear, one account in a short burst | helpdesk: call the user, renew the client or the stored password | when convenient |
| own or internal addresses | name the system behind the address (ns.conf object or network plan), check the account | this week |

Account names appear only in the original report; the anonymized copy masks them. Thresholds: README 4.2 and 4.3.

## New rules stand from ceterion

A new rules stand is published as a release tagged `rules-<date>` (rules file only) or together with a script release `v17.x`.
1. Download `ns_quickcheck.rules` from the release and check its SHA-256 against the release page.
2. Copy it to `/var/nssnapshot/`, owner `root:wheel`, mode 600; the old file is replaced. Custom file, block list, whitelist, config and mapping table stay.
3. Run once; the header shows `regeln=<date>`. If it reports that the rules file is older than the script's minimum stand, the order was reversed: rules file first, then script. An old script runs with a new rules file; a new script skips individual checks with an INFO line when the rules file is old.
4. If one of your custom lines is now in the rules file, remove the custom line (identical lines are harmless, differing fix builds produce an INFO).

## Block list

What you have blocked at the firewall, a blocklist or the appliance goes into `ns_quickcheck.blocked_ips` (template `ns_quickcheck.blocked_ips.example`): `address_or_network ; since ; remark`. The quick check shows findings for these addresses as ORANGE "covered" when the observation predates the block date, and as YELLOW "block not effective" when the address returns afterwards. The file stays with you; the remark appears only in the original report. File layout and rules: `ns_quickcheck_README.md`, section 5.4.

## Whitelist: with a hash per file

The whitelist releases files, not folders: per file exactly the reviewed version with its SHA-256. Directory rules are still supported by the script but not recommended (see WARNING below); they never cover code (`.js`, `.php`, `.pl`, `.sh`, `.cgi`, `.py`, `plugins.xml`) anyway.

After a "web files since boot" finding:
1. Assign the change (ticket, deployment log). No record, no release; then step 3 of the finding's "Zu tun".
2. Diff against the previous version (snapshot set or backup); for code read every line.
3. Generate pin lines and append them:
   ```
   sh /var/nssnapshot/ns_quickcheck.sh --pin /var/netscaler/logon/LogonPoint_workspace/custom/ >> /var/nssnapshot/ns_quickcheck.whitelist
   ```
   Result, one line per file:
   ```
   webfile:^/var/netscaler/logon/LogonPoint_workspace/custom/script\.js$@sha256=4c0e8d1f3b7a2c9e5d6f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d
   webfile:^/var/netscaler/logon/LogonPoint_workspace/custom/strings\.de\.js$@sha256=b7d2e4f6a8c0d2e4f6a8c0d2e4f6a8c0d2e4f6a8c0d2e4f6a8c0d2e4f6a803ee
   ```
   `--pin-all` instead of `--pin` also takes images, CSS and JSON when the folder is small and every change should be reported.
4. Comment line with date and ticket above, rerun, finding gone.
5. After the next update the run reports "per Hash freigegebene Web-Datei erneut geaendert" (whitelisted file changed again) with the file names; steps 2 and 3 for those only.

**WARNING, three things that make a whitelist dangerous:**

1. **A pin releases exactly that content.** Pinning a file without diffing it against the previous version can release an already manipulated file; from then on no run reports it, nor does the Collector. So: diff first (snapshot set or backup), for code read every line, only then `--pin` or `--pin-all`. When in doubt, do not pin.
2. **A file rule without a hash (`...$` without `@sha256=`) releases the name, not the content.** The file can change any number of times afterwards and the run stays silent. For code this form has been ineffective since 17.34; for images, CSS and JSON it is allowed, but `--pin-all` is the better choice.
3. **Do not use directory rules (`.../`).** They release everything below, including files that do not exist yet. Since 17.34 a directory rule never covers code, but a new image file with a payload inside a theme folder stays invisible. Replace existing directory rules with pins: `--pin-all <theme folder>` after the diff, then delete the directory rule. The run header counts directory rules as INFO.

Check whether the whitelist is still sound: `grep -c '@sha256=' ns_quickcheck.whitelist` against `grep -c '^webfile:' ns_quickcheck.whitelist`; the difference is the number of rules without a hash.

What the hash does: it binds the release to a content, not to a name. An attacker overwriting a released file produces a finding; with a directory rule he would not. Rule forms and maintenance in detail: `ns_quickcheck_README.md`, section 15, Howto Whitelist (German).

## Reports and sharing

Every run writes the original (`.txt`, `.json`, `_ips.tsv`) and an anonymised version (`_anon.txt`, `_anon.json`). Only the anonymised version leaves the appliance (issue, ticket, research prompt, ceterion), after a spot check; the mapping table `ns_quickcheck.anon.<host>.map` stays on the appliance. Run further log excerpts through `sh ns_quickcheck.sh --anon <file>` first.

Rules file and custom file format: `docs/rules-format-2.md` (binding for script and Collector).

## Rules that always apply

- A third-party compilation is a pointer to where to read, not a source. The reference is always the original publisher's publication.
- The custom file takes what you are allowed to use. Being in the file does not make a value more permitted.
- Never copy test logs or fixtures to an appliance.
- No report, bundle or log leaves without anonymisation.

## If something fails

- `rules-apply.sh` aborts: read the message, it names the line; the custom file is unchanged.
- Custom file is not loaded: `ls -l`, permissions 600, name exactly `ns_quickcheck.rules.custom` in the folder of the rules file.
- Appliance reports red after deployment: classify by the "Zu tun" lines in the report; do not delete the custom row before it is clear what it matched.
- Shell crashes ("Segmentation fault"): the custom file is rarely the reason; check the script version, open an issue with an `sh -x` trace.

## Maintenance by ceterion

The rules file follows the same workflow against `ns_quickcheck.rules` (`sh docs/rules-apply.sh ns_quickcheck.rules ns_quickcheck.rules.patch`, backup `ns_quickcheck.rules.bak_<state>`), plus prefix check, test logs, fixtures, provenance log and `docs/release.sh` before every release.
