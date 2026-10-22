# ns_quickcheck: Security triage for NetScaler ADC and Gateway

One run on the appliance, one verdict: build against the Citrix bulletins, attack traces, quick compromise check, address lists, anonymized reports. Rule-driven, works offline, extensible with your own indicators. Built in October 2026 for CTX697096, CTX697174 and CTX697191, designed for the bulletins that follow.

Script V17.29, rules file format 2 (version 2026-10-22b), README v26 en (2026-10-22, English edition of v26; German is the leading version); the version in the repository always matches the script, the history is in section 17. Apache 2.0, Copyright 2026 ceterion AG.

**Language note:** the script's output (terminal, report, finding texts in the JSON) is German only. This README therefore quotes output lines verbatim in German and gives the English meaning in parentheses where it matters. Field names, verdicts and the RESULT line are language-neutral. English output (`--language en`) is planned for V18 (section 12).

Which section is for whom: **Operators** (the admin who runs the script): 1 to 7, 10, 11, 12, 15, 16; whoever adjusts thresholds: 4.2 and 4.3. **Operators with their own indicators**: additionally 8.4 to 8.6 and WORKFLOW.md. **ceterion and power users** (rules maintenance, acceptance, tests): 8, 9, 13.

## 1. In 15 minutes

1. Download `ns_quickcheck.sh` and `ns_quickcheck.rules` from the release, check SHA-256 against the release page.
2. Copy via SCP (WinSCP: binary) to `/var/nssnapshot/` on the appliance; create the directory if it is missing (it survives reboots, unlike `/var/tmp`). There, as `nsroot`:
   ```
   mkdir -p /var/nssnapshot && cd /var/nssnapshot
   chmod 600 ns_quickcheck.sh ns_quickcheck.rules
   sh ns_quickcheck.sh
   ```
3. Read the exit code (`echo $?` right after the run): 0 `OK`, 1 `INVESTIGATE`, 2 `UPDATE` or `FORENSICS_FIRST`, 3 aborted with the reason on stderr (rules file missing, core variable missing, option without value). 1 and 2 are verdicts, not errors. If the run aborts without a `RESULT` line, repeat it with `sh -x ns_quickcheck.sh --no-out 2>/tmp/qc_trace.txt >/tmp/qc_out.txt` and send both files anonymized (`--anon`, section 5.3).
4. Read the header line: `ns_quickcheck 17.29  host=<n>  modus=online  regeln=2026-10-22b`. If it shows `cli=none`, the CLI layer is missing (section 3); the script runs anyway. Below it are the loaded operator files (custom file, blocklist, whitelist), and block 4 lists the log families read with their file counts.
5. Scroll to the end: `ACTION: OK`, `UPDATE`, `INVESTIGATE` or `FORENSICS_FIRST`. What that means is in section 7, column "Do now".
6. Before the `RESULT` line you find the external addresses of this run with their status (new or known since) and blocklist status; `coverage=full` in `RESULT` confirms that all core checks had data.
7. All further files (config, whitelist, block list, custom file, mapping table) belong in the same directory. The files of this run are in `/var/nssnapshot/quickcheck/`: report, JSON, address list, anonymized versions. Only `_anon.*` may leave the organization (section 5.3).

A clean run looks like this (shortened, anonymized; `fenster=168h` here comes from `HOURS=168` in the config, the script default is 72 h):

```
ns_quickcheck 17.29  host=gw-01  modus=online  fenster=168h  regeln=2026-10-22b  cli=nscli (user01, cli_user aus ns_snapshot.conf)
  [INFO]  Custom-Datei des Betreibers geladen: 78 aktive Indikator-Zeile(n), 0 CVE-Zeile(n) (betreiber-2026-10-20)
  [INFO]  Sperrliste: 3 Eintrag/Eintraege (ns_quickcheck.blocked_ips und ACLs der Appliance); Befunde zu gesperrten Adressen vor dem Sperrdatum werden ORANGE (abgedeckt)
Whitelist: /var/nssnapshot/ns_quickcheck.whitelist (4 Regeln)
== 1 Build ==
  [OK]    Build 14.1-73.46 enthaelt alle 11 Fix(es) fuer 14.1 der Regeldatei
  [INFO]  Letzter Boot: 2026-10-09 06:10 (12 Tage)
== 2 Exposure ==
  [OK]    Kein SAML SP/IdP - SAML-abhaengige CVEs nicht relevant
  [INFO]  DTLS an 4 Gateway-vServer aktiv (CVE-2026-88772-Voraussetzung; auf gefixtem Build mitigiert)
  [OK]    Enhanced ISN Generation aktiv
== 3 Mitigation ==
  [INFO]  Keine Mitigation-Policy gefunden (auf gefixtem Build ohne Spuren nicht erforderlich)
== 4 Angriffsspuren (letzte 168h) ==
  [INFO]  Gelesene Logs im Fenster: ns.log/nsvpn/messages/notice 84, httpaccess 15, httperror 3, auth.log 8, httpaccess.log (Management) 2, cron 4 Datei(en)
  [OK]    Keine Injection-Muster in Logon-Zeilen der letzten 168h
  [OK]    Keine nsaaad-Crashes im Fenster
  [OK]    Webserver-Fehlerlog ohne Interpreter-Fehler ausserhalb der Stock-Pfade
  [OK]    Keine Webshell-Sondierung im Webserver-Fehlerlog
  [OK]    Management-Ebene (NITRO, GUI) nur von internen Adressen angesprochen
  [INFO]  Anmeldungen an der Appliance im Fenster: console (2) nur interne Adressen
  [INFO]  Gateway-Anmeldefehler im Fenster: 14, keine Adresse ueber den Schwellen (5 Fehlversuche, 10 Konten)
== 5 Kompromittierungs-Schnellcheck ==
  [OK]    netscaler/ns_monuploadd_err.pl: Hash entspricht dem Stock-Wert fuer 14.1-73.46
  [OK]    Keine Schnellcheck-Treffer (ersetzt keinen vollen IoC-Scan)
== 6 Verdict ==
ACTION: OK
Build gefixt, keine Spuren. Naechster Lauf nach dem naechsten Bulletin oder taeglich per Cron.
RESULT host=gw-01 build=14.1-73.46 ... compromise=0 red=0 yellow=0 orange=0 coverage=full action=OK rules=2026-10-22b ...
```

The block headings read: 1 Build, 2 Exposure, 3 Mitigation, 4 attack traces, 5 quick compromise check, 6 verdict.

An exposed gateway does not look like this on most days: probes, dropper requests and failed logons are routine. What to do then is in the "Zu tun" (to do) lines of each finding and in section 15 under "Everything is yellow".

What the script does not do: it changes nothing on the appliance, does not patch, opens no network connection, sends nothing. It reads configuration, logs, file system, processes and listeners and writes reports into one directory. It is not forensics; it tells you whether forensics is needed before anyone patches.

## 2. Purpose and scope

An operator of NetScaler Gateway or ADC has to answer three questions after a bulletin: Is the build vulnerable? Are there traces of an attack? May I patch, or will the upgrade destroy evidence? The script answers all three in one run on the appliance, without dependencies, online or offline against a snapshot set.

Since 17.19 the script also checks what is not in any bulletin but happens every day: webshell probes, access to the management plane, SSH logons and attacks on gateway accounts (password spraying, brute force, slow "sleepers"), with sources, networks and blocklist status; for this it reads access, error and authentication logs in addition to the syslogs.

The assessment lives in the rules file (fix builds, conditions, indicators, patterns), not in the script; a new bulletin means a new rules version. Operators can maintain their own indicators and fix builds in a custom file (8.4). Related tools: `netscaler-snapshot` (daily file snapshot) and `netscaler-collector` (analysis across devices and time), section 14.

## 3. Prerequisites

| Item | Online (on the appliance) | Offline (admin workstation) |
|---|---|---|
| System | NetScaler 13.1 or 14.1, root shell (`shell` from the CLI) | Linux, macOS or WSL with `sh`, `perl`, `gzip`, `find`, `awk` |
| Input | running appliance | extracted snapshot archive 1 (config, manifest, state), optionally archive 3 (logs) |
| Rules file | `ns_quickcheck.rules` next to the script or via `--rules`; permissions 600 | same |
| Custom file | `ns_quickcheck.rules.custom` next to the rules file, optional, 600 | same |
| Config | `ns_quickcheck.conf` (optional) and `ns_snapshot.conf` (`CLI_*` only), root-owned, 600 | optional |
| Whitelist | `ns_quickcheck.whitelist` (optional), per appliance | optional |
| CLI layer | service user (3.1); from `ns_snapshot.conf` if the snapshot runs, otherwise from `ns_quickcheck.conf`; without it, hit counters, deny list, sessions and the diff between running and saved config are missing | not available |
| Working directory | `/var/nssnapshot/tmp` (default) or `WORK_BASE` from the config; never `/tmp`, which sits on the small root file system | `/var/tmp` |

Logs read (all under `/var/log/`, rotations `.N.gz` included, selected by modification time within the `--hours` window):

| Family | Used for | If missing in the window |
|---|---|---|
| `ns.log`, `nsvpn.log`, `messages`, `notice.log` | injection lines, nsaaad crashes, DTLS errors, gateway logons (AAA) | yellow and `coverage=partial`, the verdict is never `OK` |
| `httpaccess-vpn.log`, `httpaccess.log` | dropper requests, sources of probes, webshell paths with status 200, management access (`httpaccess.log` only) | INFO "nicht geprüft" (not checked) and `coverage=partial` |
| `httperror.log`, `httperror-vpn.log` | interpreter errors, webshell probes, direct web server access | INFO "nicht geprüft" |
| `auth.log` | SSH and console logons, failed attempts, backdoor accounts | INFO "nicht geprüft" |
| `cron` | last run of foreign crontab lines | line omitted |
| `nsinstall.log` | time of the last upgrade, for the upgrade window in block 5 | boot time only |

### 3.1 Service user for the CLI layer (optional, recommended)

Without it, hit counters of the mitigation policies, deny list, active sessions and the diff between running and saved config are missing; the verdict still works. If you run `netscaler-snapshot`, you already have the user (`CLI_USER` in `ns_snapshot.conf`) and the Quickcheck uses it as well. Otherwise set it up once per appliance. HA pair: CLI steps on the primary only (the user is synchronized), secret file on both nodes (it is not synchronized).

Check whether one already exists: `grep CLI_USER /var/nssnapshot/ns_snapshot.conf`. If a name is shown, do nothing else; the header line of the next run shows `cli=nscli (<n>, cli_user aus ns_snapshot.conf)`. If `ns_quickcheck.conf` contains its own values, those win.

The account name is your choice, here `ns-quickcheck`; if the snapshot runs, the user `ns-snapshot` already exists, then create nothing and configure nothing; NetScaler is case-sensitive, so use lowercase throughout.

Step 1, shell as root: generate and store the password
```
umask 077
mkdir -p /var/nssnapshot
openssl rand -base64 48 | tr -d '/+=\n' | cut -c1-32 > /var/nssnapshot/ns_quickcheck.secret
chown root:wheel /var/nssnapshot/ns_quickcheck.secret; chmod 600 /var/nssnapshot/ns_quickcheck.secret
cat /var/nssnapshot/ns_quickcheck.secret
```

Step 2, CLI: policy, user, binding (insert the password from step 1, then close the CLI session)
```
show system parameter
add system cmdPolicy cp_ns-quickcheck_ro ALLOW "(^show\s+(?!techsupport|system\s+(cmdPolicy|file)).*)|(^stat\s+.*)"
add system user ns-quickcheck <PASSWORD> -externalAuth DISABLED -allowedManagementInterface CLI -timeout 300 -maxsession 1
bind system user ns-quickcheck cp_ns-quickcheck_ro 100
save ns config
```
`localAuth` in `show system parameter` must be `ENABLED`. The built-in policy `read-only` is not sufficient, it excludes `show ns runningConfig`.

Step 3, shell as root: test (the second and third commands must be rejected)
```
PW=$(cat /var/nssnapshot/ns_quickcheck.secret)
/netscaler/nscli -U %%:ns-quickcheck:$PW "show ns version"; echo RC=$?
/netscaler/nscli -U %%:ns-quickcheck:$PW "save ns config"; echo RC=$?
/netscaler/nscli -U %%:ns-quickcheck:$PW "shell"; echo RC=$?
unset PW
```

Step 4: add to `ns_quickcheck.conf`, then run once; the header line shows `cli=nscli (ns-quickcheck)`.
```
CLI_USER=ns-quickcheck
CLI_SECRET_FILE=/var/nssnapshot/ns_quickcheck.secret
```

What the account can do: only `show` and `stat`, CLI only, no external authentication, one session, 300 s timeout. What it cannot do: save, change, shell, NITRO, GUI. Every query appears as `CMD_EXECUTED` in `ns.log`; the Quickcheck excludes admin commands from the assessment and automatically removes the `CLI_USER` from the check of local system users. The password is visible in the process list for a few seconds during an `nscli` call (section 10).

Removal: `unbind system user ns-quickcheck cp_ns-quickcheck_ro`, `rm system user ns-quickcheck`, `rm system cmdPolicy cp_ns-quickcheck_ro`, `save ns config`, then `rm /var/nssnapshot/ns_quickcheck.secret`.

## 4. Installation and files

### 4.1 Files and update

| File | Location | Permissions | On update |
|---|---|---|---|
| `ns_quickcheck.sh` | `/var/nssnapshot/` | 600, root:wheel | replace |
| `ns_quickcheck.rules` | next to the script | 600 | replace |
| `ns_quickcheck.rules.custom` | next to the rules file | 600 | keep |
| `ns_quickcheck.conf` | next to the script | 600 | keep |
| `ns_quickcheck.secret` | `/var/nssnapshot/` (password of the service user, 3.1) | 600, root:wheel | keep; never in reports, sets or issues |
| `ns_quickcheck.whitelist` | next to the script | 600 | keep |
| `ns_quickcheck.blocked_ips` | next to the script (operator blocklist, 5.4) | 600 | keep |
| `ns_quickcheck.anon.<host>.map` | next to the rules file, created on the first run | 600 | keep |
| Reports | `/var/nssnapshot/quickcheck/` | 600 | keep, deleted after `REPORT_KEEP_DAYS` (30) |
| `ns_quickcheck_observed_ips.tsv` | in the report directory | 600 | keep, never deleted |

Update: replace the two files, check the hash, run once. Everything else stays.

### 4.2 Configuration (`ns_quickcheck.conf`)

Optional, next to the script, 600; one line per setting `NAME=value`, missing lines use the default. Template `ns_quickcheck.conf.example`.

| Parameter | Default | Effect |
|---|---|---|
| `BASE_DIR` | `/var/nssnapshot` | location for reports (`quickcheck/`), secret, working directory |
| `WORK_BASE` | `$BASE_DIR/tmp`, fallback `/var/tmp` | temporary files and extraction for `--compare`; never `/tmp` |
| `HOURS` | 72 | log window in hours, like `--hours`; the option wins |
| `REPORT_KEEP_DAYS` | 30 | deletion of old reports; the cumulative address list is kept |
| `ACCESS_LOG_MAX_MB` | 200 | upper limit for `httpaccess*` files read, newest first |
| `CLI_TIMEOUT` | 20 | seconds per `nscli` call |
| `CLI_USER`, `CLI_SECRET_FILE` | from `ns_snapshot.conf` if the snapshot runs, otherwise here | service user (3.1) |
| `DETAIL_MAX` | 0 (all) | lines per detail list; beyond that "... und n weitere" (and n more) |
| `LINE_MAX` | 400 | characters per log line in terminal and report; 0 = not truncated; injection lines always complete |
| `MGMT_NET_RE` | empty (only RFC 1918 counts as internal) | ERE of admin networks and jump hosts; applies to management access, SSH logons, direct web server access and own addresses in failed logons |
| `PROBE_LEVEL` | `yellow` | `info` downgrades webshell probes to one INFO line |
| `AAA_FAIL_IP` | 5 | failed gateway logons per address from which the address is assessed |
| `AAA_FAIL_USERS` | 10 | distinct accounts per address from which it counts as machine |
| `AAA_RATE` | 10 | failed attempts per minute from which an address counts as machine |
| `AAA_OK_WIN` | 5 | minutes after the last failed attempt within which a success of the same account from the same address means "user" |
| `AAA_BF_MIN` | 20 | failed attempts on a single account from which it counts as brute force |
| `AAA_SLEEPER_DAYS` | 2 | days with attempts, or span between first and last attempt, from which an address counts as sleeper |

### 4.3 Thresholds and assumptions

The assessments in blocks 4 and 5 are based on thresholds calibrated on a lab gateway. Each one is documented and, where it makes sense, configurable. If you get false positives, turn the knob named in the table; if something slips through, turn it the other way.

| Assumption | Default | False positive when | Missed when |
|---|---|---|---|
| Dropper search: more than two different package names from one address, or command characters in the query string | fixed | never observed; real clients request one package | attacker with exactly one package name shows as yellow, not red |
| Upgrade window: file changes up to 15 min after boot and 30 min after the last upgrade (`nsinstall.log`) count as upgrade | fixed | attacker who writes within the half hour after the upgrade | very long upgrades (over 30 min) produce yellow for stock files; whitelist |
| Machine: from `AAA_RATE`/min or `AAA_FAIL_USERS` accounts per address, or address from a /24 with at least two machines | 10, 10 | corporate proxy with many users failing on the same morning (comes out as "user" as soon as one logs on) | sprayer below 10/min with fewer than 10 accounts per address: the sleeper logic covers this |
| User: success of the same account from the same address within `AAA_OK_WIN` | 5 min | attacker who guesses a password (then a hit, red, if the address is a machine) | helpdesk case after 40 min stays "unclear" and disappears with the next run |
| Burst: one account, at least 3 attempts/min, all within 10 min | fixed | a very fast human | client with an old password retrying more slowly is listed as "unclear" |
| Sleeper: several accounts, no success, attempts on `AAA_SLEEPER_DAYS` days or across that span | 2 | user who tries two accounts on two days and gives up (rare; the account list in the original report shows it) | with 1, every multi-account address without success would be called sleeper and the time axis would be lost |
| Brute force: `AAA_BF_MIN` failed attempts on one account or `AAA_RATE`/min on one account, from any number of addresses | 20 | a user with 20 failed attempts and no success (then listed with account and address in the report, usually the helpdesk call) | patient attacker below 20 attempts in the window: sleeper logic |
| Hit: success after a failure series of a machine (same address and account) or after brute force on an account (from any address) | fixed | the user logs on after the attack: hence "ein Mensch muss das entscheiden" (a human has to decide) | never suppressed; red stays red |
| Source IP for logon lines: request at the attempt time, plus/minus 5 s, offset search up to 14 h | fixed | unrelated logon in the same second (hence "passt zu n von m" (matches n of m) and "schwach" (weak)) | a single attempt yields no source (by design) |
| Source IP for responder lines: only from the line itself | fixed | none | policy without audit message action: source unknown (howto "Responder source") |
| Webshell probe: 404 for known webshell names | fixed | none, the names are unambiguous | attacker with a custom file name: only via block 5 and the 200 check |

Cron (daily after the snapshot, persistent across reboots via `/nsconfig/rc.netscaler`):
```
# /nsconfig/rc.netscaler
echo '45 3 * * * root /bin/sh /var/nssnapshot/ns_quickcheck.sh --compare cron --brief >> /var/nssnapshot/quickcheck/cron.log 2>&1' >> /etc/crontab
```
`--brief` keeps the cron log short; the full report is still written.

## 5. Usage

Every option that takes a value accepts two forms: `--option value` and `--option=value`. If the value is missing, the script aborts with exit code 3 and a message.

| Option | Value | Effect | Default |
|---|---|---|---|
| `--hours` | hours | log window: only log files modified within the last n hours; also as `HOURS=` in the config | 72 |
| `--from` | path | offline run against an extracted snapshot set (archive 1, optionally archive 3) | online |
| `--compare` | `cron`, `latest` or path | comparison against the latest complete set, the latest set or an extracted archive 1: new or changed web files, new system users, new listeners | no comparison |
| `--rules` | path | rules file; `ns_quickcheck.rules.custom` is looked for in the same folder | next to the script, otherwise `/var/nssnapshot/` |
| `--whitelist` | path | whitelist per appliance (`user:`, `listener:`, `path:`, `cron:`, `webfile:`) | next to the script |
| `--blocked` | path | operator blocklist (5.4) | `ns_quickcheck.blocked_ips` next to the script |
| `--conf` | path | configuration file (`BASE_DIR`, `WORK_BASE`, `HOURS`, `REPORT_KEEP_DAYS`, `ACCESS_LOG_MAX_MB`, `CLI_TIMEOUT`, `DETAIL_MAX`, `MGMT_NET_RE`, `PROBE_LEVEL`, `LINE_MAX`, `AAA_FAIL_IP`, `AAA_FAIL_USERS`, `AAA_RATE`, `AAA_OK_WIN`, `AAA_BF_MIN`, `AAA_SLEEPER_DAYS`, `CLI_USER`, `CLI_SECRET_FILE`); loaded before all other options | next to the script |
| `--out` | path | report file; JSON, address list and anon versions next to it | `/var/nssnapshot/quickcheck/ns_quickcheck_<host>_<time>.txt` |
| `--no-out` | | no report, screen only; no anon files, no address list | |
| `--anon` | file | anonymize any log excerpt with this appliance's mapping table, output to stdout, nothing else | |
| `--full` | | everything on screen (the default since 17.2; option kept for scripts) | |
| `--brief` | | only findings and summary lines on screen; report stays complete; for cron mails | |
| `--no-cli` | | skip the CLI layer even if a service user is configured (faster; no hit counters, sessions, config diff) | |
| `--testlog` | folder or file | test rule patterns against test logs, expectations from `expected.txt`; workstation only, never on an appliance | |
| `--ki-bundle` | | anonymized material for rules maintenance to `/var/tmp`; only for acceptance on a new build family | |
| `--version` | | print the script version and exit | |

Examples:
```
sh ns_quickcheck.sh                                         # standard online run
sh ns_quickcheck.sh --compare cron --brief                  # cron: compare against the last complete set, short output
sh ns_quickcheck.sh --from /var/nssnapshot/tmp/x --rules /var/nssnapshot/ns_quickcheck.rules   # offline against an extracted set
sh ns_quickcheck.sh --anon /var/log/ns.log.1 > /var/tmp/ns.log.1.anon                          # anonymize a log excerpt
sh ns_quickcheck.sh --anon=/var/tmp/auszug.txt                                                  # same option with equals sign
```

### 5.1 Report files per run

| File | Content | May leave the organization |
|---|---|---|
| `ns_quickcheck_<host>_<time>.txt` | the report, as on screen | no |
| `ns_quickcheck_<host>_<time>.json` | RESULT fields, `text` and `details` per finding, `observed_ips`, `mitigation_hits`; addresses defanged | no |
| `ns_quickcheck_<host>_<time>_ips.tsv` | external addresses observed in this run, per category (5.2) | after review |
| `ns_quickcheck_observed_ips.tsv` | cumulative address list of the appliance across all runs (5.2) | after review |
| `ns_quickcheck_<substitute host>_<time>_anon.txt` and `_anon.json` | anonymized versions (5.3) | yes, after spot check |

### 5.2 Address list

For each run the script writes `ns_quickcheck_<host>_<time>_ips.tsv` to the report directory (header lines starting with `#`, then one entry per line: category, address, count, observation, tab-separated); the same entries are in the JSON as `observed_ips`. The anon versions contain the addresses as well, because they are external addresses. The list contains the external addresses the device saw in this run, for firewall and SOC:

| Category | Origin | For the blocklist |
|---|---|---|
| `webshell_probe`, `webserver_direct` | sources of requests to non-existent webshell paths; clients that reached the web server bypassing the Packet Engine | high: targeted probing |
| `webshell_hit` | source of a request to a webshell path that answered with 200 | very high: sign of compromise |
| `aaa_bruteforce`, `aaa_sleeper`, `aaa_hit` | machine addresses with failed gateway logons; `aaa_sleeper`: slow spraying over days; `aaa_hit`: success after a failure series, account compromised | high; `aaa_hit`: act immediately |
| `mgmt_access`, `ssh_login_external`, `ssh_bruteforce` | management paths, SSH logons and failed attempts from addresses outside RFC 1918 and `MGMT_NET_RE` | review: put admin networks into `MGMT_NET_RE`, otherwise block |
| `payload_download_host` | address in the injection payload (`curl ... <address>`) | high: attacker infrastructure |
| `injection_source` | logon request at the attempt time in the access log | high; behind NAT only the NAT address |
| `dropper_requester` | requests to nsgclient paths, with count | review: real Linux clients request the same paths |
| `outbound_hit` | active connection to a known attacker address | high |

In addition, the script keeps the cumulative list `ns_quickcheck_observed_ips.tsv` per appliance in the same directory, updated with every run and never deleted by the report retention, with eleven columns: `kategorie` (category), `adresse` (address), `anzahl_zuletzt` (hits in the last run), `zuletzt_fenster_h`, `anzahl_max`, `max_fenster_h`, `tage` (calendar days with observations, several runs on one day count once), `zuerst_gesehen` (first seen), `zuletzt_gesehen` (last seen), `beobachtung` (observation), `gesperrt` (blocked: remark and date from the blocklist; internal, remove before passing on). No totals: every run reads the same logs again. The same address can appear in two categories; those are two roles. The terminal line "Adressliste dieses Laufs: n Einträge, davon m neu gegenüber dem Bestand" (address list of this run: n entries, m of them new) is the line an admin acts on: an address that has been requesting dropper paths daily for weeks is a different finding from one that shows up for the first time today.

For firewall import: `grep -v '^#' ns_quickcheck_observed_ips.tsv | cut -f2 | sort -u` returns the plain address list.

Own and RFC 1918 addresses are never included. Before building a blocklist, check: shared infrastructure (CDN, Cloudflare WARP, proxies, NAT) blocks uninvolved parties too. The list contains what was observed, not the indicators of the rules file; if you want the whole rules file as a blocklist, take it from the IOC section.

### 5.3 Anonymization

| Topic | Content |
|---|---|
| What is replaced | addresses from `ns.conf` (NSIP, SNIP, vServer, server, HA peer, auth server) and every RFC 1918 address in the text; host name and HA peer; system users except `nsroot` and known backdoor accounts; auth server names, FQDNs from server objects and monitors, DNS suffixes, e-mail addresses; object names from `ns.conf` (vServers, policies, actions, profiles, servers, certificates, themes) of four characters or more, certificate and key file names, DN components from `bindDn` and `ldapBase`; theme directories outside the stock themes |
| What is masked (no table, always `***`) | values after secret parameters (`-password`, `-ldapBindDnPassword`, `-radKey`, `-tacacsSecret`, `-secret`, `-sharedSecret`, `-clientSecret`, `-pskKey`, `-community`, `-tsigKey`, `-passplain`), password hashes of system users, SNMP communities, encrypted blocks before `-encrypted`. Comment lines of an `ns.conf` become "# (Kommentar entfernt)" (comment removed) |
| Replaced with | stable per appliance: addresses `198.51.100.n` (from 255 on `203.0.113.n`), hosts `gw-01`, `gw-02`, users `user01`, domains `example1.net`, mail `user1@example.net`, objects `obj001`, themes `theme01` |
| What stays | attacker addresses and domains, hashes, paths, timestamps, build, rules versions, SHA-256, backdoor account names |
| Mapping table | `ns_quickcheck.anon.<host>.map` next to the rules file, one per appliance (for host name `gw-frankfurt` it is `ns_quickcheck.anon.gw-frankfurt.map`); permissions 600; grows with every run, substitute names never change; stays on the appliance, never goes into the snapshot set, never into the repo, never to third parties. Deleting it means new substitute names on the next run; old and new anon reports can then no longer be compared |
| File names | anon reports carry the substitute host: `ns_quickcheck_gw-01_<time>_anon.txt`; the real host appears only in the original and in the table name |
| `--anon <file>` | any log excerpt or an `ns.conf`, with the same table, for issues, support cases and the research prompt: `sh ns_quickcheck.sh --anon /var/log/ns.log.1 > /var/tmp/ns.log.1.anon`, `sh ns_quickcheck.sh --anon /nsconfig/ns.conf > /var/tmp/ns.conf.anon`; stderr shows how many mappings and secrets were replaced |
| Limits | only recognizes what is in `ns.conf` or is private. Other host names, AD user names in logon lines, public customer IPs in log lines and free text in policy expressions (`HTTP.REQ.URL.CONTAINS("kunde")`) remain in clear text. That is why every anon file carries "Stichprobe vor Weitergabe" (spot check before passing on) in its header |
| Reading aid | an anon report reads like the original; `obj001` in a responder line is the policy, `theme01` your own theme. If you need the mapping, you have the original |

### 5.4 Operator blocklist

`ns_quickcheck.blocked_ips` next to the script (template `ns_quickcheck.blocked_ips.example`, 600, kept on update, never distributed): what the firewall, a blocklist feed or the appliance already blocks. Line: `adresse_oder_netz ; seit ; Bemerkung` (address or network; since; remark); only the address is mandatory, without a date it is only marked. Skipped lines (no valid IPv4 address or network) are listed in the header line with their line number. ACLs of the appliance (`add ns simpleacl` and `add ns acl` with DENY) automatically count as blocked, without a date.

**File layout**

One line per address or network, fields separated by semicolons (spaces do not matter, tabs allowed), comments with `#`:

```
# address_or_network ; since ; remark
203.0.113.44    ; 2026-10-20 ; fw-zentral, INC-4711, download host injection 19 Oct
192.0.2.0/24    ; 2026-10-21 ; fw-zentral, INC-4711, dropper search, whole range
203.0.113.126   ; 2026-10-21 ; access portal blacklist (FW)
203.0.113.9     ;            ; SOC blocklist, date unknown: only marked
```

| Field | Mandatory | Content | Appears in |
|---|---|---|---|
| 1 address or network | yes | IPv4 or CIDR (`/24`); no IPv6 | finding lines, anon report, address lists |
| 2 since | for ORANGE | `YYYY-MM-DD`, the day from which the block is effective; empty = only marked | finding lines ("Sperre ab 2026-10-21", blocked since), anon report, address lists |
| 3 remark | no | internal: where the block is, ticket, colleague, reason | original report (`[Bemerkung: ...]`) and address lists, never anon versions |

Finding text: `203.0.113.126: Sperre ab 2026-10-21 [Bemerkung: ...], letzte Beobachtung 2026-10-20, 12 Request(s)`; in the anon version without the remark part. Lines without a valid IPv4 address are listed in the header line with their line number, lines without a date are counted ("n ohne Datum: nur markiert", n without date: only marked). ACLs of the appliance (`add ns simpleacl`, `add ns acl` with DENY) are added automatically as blocked without a date. Maintenance: enter the firewall's date, not the report's; a lifted block means deleting the line. If the date of an observation cannot be determined (log line without a readable timestamp), the report says so and assesses it as not blocked.

Effect, as a fourth level ORANGE "abgedeckt" (covered):

| Finding | blocked, observation before the block date | blocked, observation after | not blocked |
|---|---|---|---|
| Injection attempt with download host | ORANGE | RED | RED |
| Dropper requests, dropper search | ORANGE per address ("abgedeckt", with Zu tun: nothing) | YELLOW "Sperre greift nicht" (block not effective) with count and last date | YELLOW or RED |
| Active connection to an attacker address | RED | RED | RED |
| Payload file, webshell, backdoor account | RED (a block changes nothing about what is on the appliance) | RED | RED |

Orange counts neither as a trace nor as a sign of compromise. If only orange findings remain, the verdict is `OK` with the note that the next run checks whether the blocks hold. Without a date (appliance ACL, empty field) an address is only marked ("gesperrt, Datum unbekannt: nur markiert", blocked, date unknown: only marked), not covered. Address lists get the column `gesperrt` (`bemerkung|seit`, internal, remove before passing on), RESULT gets the fields `orange=` and `blocked_seen=`, the JSON gets the list `orange` and `blocked` per address.

The script does not set any block and does not check whether the firewall rule exists; the file documents what the operator says, and the access log shows whether it is true.

## 6. The six blocks

Detail lists (log lines, paths, addresses, sessions) are shown in full in terminal and report; `DETAIL_MAX` in the config limits them if needed, then "... und n weitere" appears below. Every finding (red, yellow, orange) has detail lines with fixed labels: "Wann" (when), "Log" (file and hit count), "Ergebnis" (result), "Download-Host" or "Adresse" (address; per address: blocklist, rules file, address list), "Quelle" (source), "Netze" (networks, sources grouped per /24), "Zu tun" (to do, numbered). Log lines are truncated to `LINE_MAX` characters (default 400, 0 = not truncated); injection lines are always complete. The header line names the technical term, the detail lines answer the four questions when, what, from where, what to do. Before the RESULT line there is the list of addresses of this run with their status compared to the existing list (new or known since, number of days; several runs on the same day count once) and blocklist status.

### Block 1 Build

| Check | Source | Assessment |
|---|---|---|
| running build against every line of the `CVE_TABLE` (condition `all`, `conf:<regex>` only if it matches in `ns.conf`, `tcpparam:`) | `kern.bootfile` online, `meta.tsv` offline, fallback `ns.conf` header | red "VERWUNDBAR" (vulnerable) per open CVE with target build; OK if all fixes are included |
| lines from the custom file | CVE block of the custom file, marked `[custom]` | as above; if the rules file differs, both lines appear and the stricter result counts |
| end-of-life train (`EOL_RELEASES`) | rules file | red, no fix available |
| saved vs. running config | `ns.conf` header | yellow: `save ns config` missing |
| build with known problems | `BUILD_WARN_*` | yellow |
| staged build | `/flash/ns-*.gz` newer than boot | yellow: reboot pending |

### Block 2 Exposure

| Check | Assessment |
|---|---|
| SAML SP or IdP | info; the SAML CVEs are assessed in block 1 via the condition |
| DTLS on gateway vServers | info, mitigated on a fixed build |
| configuration steps (`tcpparam:` lines, currently Enhanced ISN Generation) | yellow if the parameter is missing; stays open after the upgrade |
| admin partitions | info, check them separately |
| management access on SNIP | yellow (NITRO reachable) |

### Block 3 Mitigation

Finds responder and traffic policies whose rule contains a pattern from `MITIGATION_RULE_RE`. Policy present, not bound: yellow. Bound, feature disabled: yellow. Bound, not `AAA_REQUEST`: yellow. Correctly bound: OK with hit counter and delta to the last run. No policy: yellow on a vulnerable build, otherwise info.

### Block 4 Attack traces

Log files are selected by modification time (`--hours`); the block header line names the families read and the file counts. Admin commands (`CMD_EXECUTED`) are excluded. If a family or a rule for it is missing, an INFO "nicht geprüft" (not checked) with the reason is shown. The checks in four groups:

**4a Traces of the bulletin CVEs**

| Check | Assessment |
|---|---|
| injection patterns in logon lines (`ns.log`, `nsvpn.log`, `messages`, `notice.log`) | red with time range, complete lines, download hosts from the payload with blocklist, rules file and address list; on a fixed build "Versuch ohne Wirkung" (attempt without effect), with a blocked download host orange |
| source of the attempt | for logon lines: logon requests in the access log at the attempt time with offset search, reported as "passt zu n von m Versuchszeiten" (matches n of m attempt times), "schwach" (weak) for one match out of several; for responder lines: from the line itself (`from IP`, `Client_ip`, `CLIENT.IP.SRC`), because the request never reached the web server; otherwise "unbekannt" (unknown) with the reason |
| nsaaad crash lines and core dumps | red with SAML on an unfixed build, otherwise yellow |
| DTLS handshake errors plus Packet Engine restart | red |
| requests to dropper paths per source IP | yellow with addresses, paths, networks; red "Dropper-Suche, kein Client" (dropper search, not a client) (more than two package names or command characters in the query string, or source IP with an injection line); blocked addresses orange or "Sperre greift nicht" |

**4b Web server**

| Check | Assessment |
|---|---|
| interpreter errors outside the management interface (`httperror*`, `HTTPERR_EXEC_RE`) | red: PHP or CGI ran outside admin_ui |
| webshell path with status 200 in the access log | red, sign of compromise; address list `webshell_hit` |
| webshell probe: "File does not exist" for webshell names, PHP variants, scanner paths and the file names from `PAYLOAD_PATHS` (`HTTPERR_PROBE_RE`) | yellow "Versuch ohne Wirkung" with paths, time range, sources from the access log, networks, blocklist status; address list `webshell_probe`; `PROBE_LEVEL=info` turns it into INFO. Note in the block: `[client 127.0.0.2]` is the appliance itself (glossary) |
| client in the error log outside 127.0.0.x | yellow "Webserver direkt angesprochen" (web server accessed directly); address list `webserver_direct` |

**4c Management and SSH**

| Check | Assessment |
|---|---|
| NITRO and GUI requests (`httpaccess.log` of the NSIP, `MGMT_PATH_RE`) from addresses outside RFC 1918 and `MGMT_NET_RE` | yellow with addresses; address list `mgmt_access` |
| SSH and console logons (`auth.log`): logons from outside, backdoor accounts, series of failed attempts from 10 per address | yellow; red on logon of a known backdoor account; address lists `ssh_login_external`, `ssh_bruteforce`; otherwise INFO with the logons (without `#nsinternal#`) |

**4d Gateway accounts (AAA, `ns.log`)** in this order:

| Finding | Definition | Assessment |
|---|---|---|
| Hit | success after a failure series of a machine (same address, same account, within `AAA_OK_WIN`) or after brute force on an account (from any address) | **red**, sign of compromise; address list `aaa_hit`; lock the account, reset the password, `kill aaa session -userName`, check MFA; "ein Mensch muss das entscheiden" (a human has to decide) |
| Brute force | one account with at least `AAA_BF_MIN` failed attempts or `AAA_RATE`/min, from any number of addresses | yellow with account, failed attempts, addresses, time range, rate; address list `aaa_bruteforce`; howto "Lockout" |
| Sleeper | address with several accounts, no success, below machine rate, attempts on at least `AAA_SLEEPER_DAYS` days or across that span (window or cumulative address list) | yellow "langsames Spraying über Tage" (slow spraying over days); address list `aaa_sleeper`; block |
| Password spraying | per address from `AAA_FAIL_IP` failed attempts or `AAA_FAIL_USERS` accounts, one line with failed attempts, accounts, time range, rate, "Erfolg danach" (success afterwards) and assessment: machine (rate, accounts or /24 with at least two machines), user (success afterwards), unclear (human rate without success; one account in a short burst is named as a likely client with an old password) | yellow; networks on top; order: unclear (at most 10), machines (at most 10), users as a count; attacked accounts with count; number of accounts that occur only once; address list `aaa_bruteforce` for machines |
| Own or internal addresses | failed attempts from `ns.conf` addresses (with object name), RFC 1918 or `MGMT_NET_RE` | yellow, separate finding: service account, monitoring, admin test, NAT egress or internal host; never in address lists; success after a failure series is red |

Account names appear in the original report (`[Bemerkung: Konten ...]` and the account list); the anon version masks them via the mapping table.

The assessments machine, user and unclear appear in the output as "Maschine", "Nutzer" and "unklar".

### Block 5 Quick compromise check

| Check | Assessment |
|---|---|
| known payload paths (IOC `path` from rules file and custom file) | red, with source and date of the indicator |
| webshell file names and PHP outside the stock directories | red |
| web files changed since boot (outside the upgrade window: 15 min after boot and 30 min after the last upgrade according to `nsinstall.log`) | yellow, a burst of 5 or more files within 30 s as "Rewrite"; explanatory line: theme customization is typical, report `.php` or paths outside the theme; whitelist `webfile:` |
| `httpd.conf` not changed at boot time | yellow if the content is unremarkable (timestamp only); red for an alias outside `STOCK_ALIAS_ROOTS` or a PHP handler in `/vpns`, `/logon`, `/epa` |
| root crontab outside `ALLOWED_CRON_RE`; crontab for `nobody` | yellow; red |
| listeners of interpreter and shell processes | stock (`KNOWN_LISTENER_RE`) no finding; unknown on loopback yellow, otherwise red; whitelist `listener:` |
| active connection to download host or attacker address (IOC `ip`, `dom`) | red |
| changes from `ns.conf.0` to `ns.conf` on security-relevant objects; unsaved lines (CLI layer) | yellow; red for user, auth or policy lines |
| `--compare`: web files, system users, listeners new since the snapshot | yellow; red for new users |
| local system users besides `nsroot`, service user and whitelist `user:` | yellow; known backdoor accounts red |
| suspicious processes (`SUSPECT_PROC_RE`) with parent check; stock hash of `ns_monuploadd_err.pl` | info for a stock parent, otherwise red; red on hash mismatch |
| EPA default `NO_AUTH`; `/bin/sh` setuid | red |

False positives (own monitoring, theme edits, service accounts) are excluded per appliance with `ns_quickcheck.whitelist`: one rule per line `<type>:<regex>`, types `user`, `listener`, `path`, `cron`, `webfile`.

### Block 6 Verdict

Section 7.

## 7. Verdict: what it means and what to do now

| Verdict | Exit | Meaning | Do now | Then | Who is informed |
|---|---|---|---|---|---|
| `OK` | 0 | build fixed, no traces, nothing open; orange findings (covered by blocks) may remain | nothing; with orange, wait for the next run, which shows whether the blocks hold | next run after the next bulletin or via cron | nobody |
| `INVESTIGATE` | 1 | build fixed, no signs of compromise, but observations someone has to classify (attempt blocked, dropper requests, changed files) | work through the "Zu tun" lines: access log, firewall log, ticket for the theme change; address list to firewall/SOC | run again; once the items are resolved or whitelisted, it becomes `OK` | security officer for attempts with a download host |
| `UPDATE` | 2 | build vulnerable or end of life, no traces | back up first (`show techsupport`, `/var/log` to external storage), then patch to the target build from block 1; HA: secondary first | after the upgrade `save ns config`, set Enhanced ISN, run again | change owner |
| `FORENSICS_FIRST` | 2 | signs of compromise: payload file, webshell, backdoor account, active connection to an attacker address, nsaaad crash with an open SAML CVE | do not patch, do not reboot: the upgrade overwrites traces. Isolate the appliance (disable the gateway vServer), start the incident process | forensics decides; then rebuild or upgrade | management, security officer, authorities if required |

### 7.1 RESULT line

`RESULT host=... build=... mode=online|offline cli=... window=<h>h saml=0|1 vuln96=0|1 vuln79=0|1 isn_open=0|1 traces=0|1 mitigation=0|1 unsaved=0|1 save_missing=0|1 compromise=0|1 red=<n> yellow=<n> orange=<n> blocked_seen=<n> coverage=full|partial action=<verdict> rules=<rules version> script_sha256=... rules_sha256=... custom=<version|none> custom_sha256=... cve_custom=<n> cve_conflict=<n> runtime=<s>s`

`coverage`: `full`, or `partial` if a core check had no data (ns.log or httpaccess family missing in the window, file not readable); with `partial` the verdict is never `OK`. `vuln96`: a CVE from CTX697096 is open. `vuln79`: at least one SAML-dependent CVE is open. `cve_conflict`: rules file and custom file assess a CVE differently.

Two rules that override the findings: `coverage=partial` (above) never makes the verdict `OK` but `INVESTIGATE`, with the line "Nicht vollständig geprüft" (not fully checked); orange findings (covered by blocks) do not count as traces, a run with only orange is `OK`.

### 7.2 JSON

```
{ "script": "ns_quickcheck", "version": "17.29", "host": "...", "ts": "...",
  "result": { ...all RESULT fields... },
  "mitigation_hits": { "<policy>": "<hits>" },
  "observed_ips": [ { "category": "dropper_requester", "ip": "...", "count": 24, "observed_in": "httpaccess DROPPER_PATH_RE", "blocked": "fw-zentral|2026-10-21" } ],
  "red":    [ { "text": "...", "details": [ "..." ] } ],
  "yellow": [ { "text": "...", "details": [ "..." ] } ],
  "orange": [ { "text": "...", "details": [ "..." ] } ] }
```
URLs are defanged (`hxxp`); addresses are not masked. The JSON is meant for ticket systems and the collector; what leaves the organization is the `_anon.json`.

## 8. Rules file, custom file, provenance

### 8.1 Rules file format 2

The rules file contains check patterns (regex variables), the `CVE_TABLE` (one line per CVE, train and condition) and the IOC section: one line per indicator with type, value, source, publication date, class, source reference at the original publisher and the rules version in which it was added. Normative description: `docs/rules-format-2.md`. Maintained by ceterion; operators do not change the file (8.4).

Rule variables the script expects (if a core variable is missing, exit 3; if a newer one is missing, the check is skipped with an INFO and the header line names the minimum version `RULES_MIN`):

| Group | Variables |
|---|---|
| Core (mandatory) | `RULES_VERSION`, `TRIGGER_RE`, `OBFUSC_RE`, `CMD_NAMES`, `LOGON_HINT_RE`, `ADMIN_CMD_RE`, `CVE_TABLE` |
| Bulletin traces | `NSAAAD_CRASH_RE`, `DTLS_FAIL_RE`, `PPE_CRASH_RE`, `LOGIN_PATH_RE`, `DROPPER_PATH_RE`, `MITIGATION_RULE_RE`, `EOL_RELEASES`, `BUILD_WARN_*` |
| Block 5 | `PAYLOAD_PATHS`, `STOCK_ALIAS_ROOTS`, `ALLOWED_CRON_RE`, `KNOWN_LISTENER_RE`, `SUSPECT_PROC_RE`, `SUSPECT_PROC_PARENT_OK_RE`, `STOCK_FILE_HASHES` |
| since 2026-10-21 (logs) | `HTTPERR_EXEC_RE`, `HTTPERR_PROBE_RE`, `AUTH_LOGIN_RE`, `AUTH_FAIL_RE`, `MGMT_PATH_RE` |
| since 2026-10-21c/d (AAA) | `AAA_FAIL_RE`, `AAA_OK_RE` |
| IOC section | lines `ip`, `dom`, `hash`, `path`; from these the script builds `ATTACKER_IP_RE`, `ATTACKER_DOM_RE` (with boundaries, case-insensitive) and the path and hash lists |

### 8.2 Provenance record

| Topic | Content |
|---|---|
| Files | `ns_quickcheck.rules.provenance.csv` (semicolon-separated, for spreadsheets and the collector) and `.md` (readable), in the repo next to the rules file |
| How it is created | `docs/provenance.sh` generates them from the rules file, anew with every release; never maintained by hand, never older than the rules file |
| Content | per indicator: type, value, source, publication date at the original publisher, source reference, status, rules version; per CVE line: CVE, train, fix build, bulletin URL |
| Purpose | the answer to "where does this value come from" in one line; basis for CREDITS.md; proof that no value is distributed without an original publisher |
| Status | 151 lines, all with a source reference (111 indicators, 40 CVE lines). Values without a source reference are not in the rules file |
| Custom file | not included; `sh docs/provenance.sh ns_quickcheck.rules.custom` produces the same for the operator's file |
| Limit | the date is the publication date, not the date we retrieved it; the retrieval evidence is in the research runs (`research_<date>.md`) in the operator folder |

### 8.3 Principles of rules maintenance

- Compilations by third parties (community scanners, aggregator pages) are pointers, not sources; the source reference is always the original publisher's publication. Values without an original publisher stay inactive (`PRUEFEN`).
- The rules file is only extended, never shortened; a removal requires a changelog entry with a justification.
- At startup the script checks that the core variables of the rules file are present (`RULES_VERSION`, `TRIGGER_RE`, `OBFUSC_RE`, `CMD_NAMES`, `LOGON_HINT_RE`, `ADMIN_CMD_RE`, `CVE_TABLE`); if one is missing, it aborts with exit 3 instead of running with empty patterns.
- Every rules version goes through `docs/release.sh`: platform lints 1 to 3, format 2 lint, prefix check, 54 test logs, 6 fixtures, provenance record.
- Regex: POSIX ERE without GNU extensions, semantics always "line matches yes/no" (`rules-format-2.md`).

### 8.4 Operator custom file

`ns_quickcheck.rules.custom` next to the rules file, template `ns_quickcheck.rules.custom.example`. Two blocks: IOC (own indicators, same columns as the rules file) and CVE (own fix build lines in `CVE_TABLE` format, for example for a bulletin ceterion has not yet covered). Both are checked in addition; if the fix build differs, block 1 shows both lines and the stricter result counts. A custom line can never make a device greener than the rules file does. The file is kept on update, never distributed, and only takes what the operator is allowed to use. Procedure: WORKFLOW.md.

### 8.5 Applying a patch

`sh docs/rules-apply.sh <target> <patch>` backs up the target as `<target>.bak_<version>`, checks every new line (format, source reference, duplicates, for CVE lines deviation from the rules file) and updates the target in place. For operators the target is the custom file, for ceterion the rules file. A three-argument form (`<old> <new> <patch>`) exists for tests.

### 8.6 Prompts

`ns_quickcheck_research_prompt.md` (research: new bulletins, reports, verification of source references) and `ns_quickcheck_rules_prompt.md` (rules: a patch from a bulletin or report). Two separate chats; results are reviewed, never adopted unchecked. Usage in WORKFLOW.md.

### 8.7 Relation to community checkers

Community tools check the same bulletins with indicator collections of their own. The quick check takes no values from them, only from the original publications with their reference (section 8.2); the projects are separate. For the widest coverage, run several tools and compare the findings.

## 9. Validation status and acceptance procedure

**Validated:** NetScaler 14.1-73.41 and 14.1-73.46 (MPX, lab): online runs with `--compare cron`, offline runs against snapshot sets and fixtures, custom file, blocklist, anonymization; on 21 Oct 2026 eleven lab runs on an exposed gateway with an ongoing spraying campaign (1,700 failed logons, 60 machine addresses, webshell probes, injection attempt), from which the finding blocks and thresholds are derived. Test basis: 54 test logs, 6 fixtures, three platform lints. **Beta:** 13.1, 13.1-FIPS, 14.1-FIPS and 14.1 appliances with features the lab did not have (SAML, AppFW, Bot, GSLB, admin partitions, custom themes, mitigation policies); expect two to five false positives on the first run there.

**Acceptance on every new appliance before the first assessment:**
1. First run with trace: `sh -x ns_quickcheck.sh --no-out 2>/tmp/qc_trace.txt >/tmp/qc_out.txt; echo EXIT=$?`. Exit 139 means a crash; `tail /tmp/qc_trace.txt` shows the line; open an issue with the trace.
2. Read the output completely. Classify every red and yellow line: stock state of the build, operator configuration, or finding.
3. Report stock states to ceterion as an issue (rules file), put operator-specific items into `ns_quickcheck.whitelist`.
4. Second run. Only when every remaining line is a classified finding does the verdict count.
5. File the record: trace, both reports (anon), classification per line, hashes from the RESULT line.

Budget: 15 minutes per appliance type. Skip it and the operator gets a `FORENSICS_FIRST` on a clean appliance.

## 10. Security considerations: what the script does on the system

**Privileges.** Runs as `nsroot` in the shell, because logs, `/nsconfig`, process list and sockets are readable only by root. It sets no privileges of its own, creates no users, changes no files outside its output directories.

**Reads.** `ns.conf`, `ns.conf.0`, `httpd.conf`, `/var/log/*` within the time window (including `.gz`: `ns.log`, `nsvpn.log`, `messages`, `notice.log`, `httpaccess*`, `httperror*`, `auth.log`, `cron`), `/var/netscaler/logon`, `/var/vpn`, `/netscaler`, `/var/tmp`, `/tmp`, `/etc/crontab` and `/var/cron/tabs`, `/var/core`, `/flash/ns-*.gz`; process list (`ps`), listeners and connections (`sockstat`, `netstat`), `sysctl kern.bootfile`. Via the CLI layer (optional) only `show` commands: `show ns runningConfig`, `show responder policy`, `show aaa session`, `show ns simpleacl`, `show ns version`.

**Writes.** Reports, JSON, address lists and anon versions to `/var/nssnapshot/quickcheck/` (600); the mapping table `ns_quickcheck.anon.<host>.map` next to the rules file (600); temporary files to `/var/nssnapshot/tmp/qc.XXXXXX` (700), deleted at the end, also on abort. Nothing else: no `save ns config`, no `set`, no `add`, no deletion of operator files; the retention deletes only its own reports older than `REPORT_KEEP_DAYS`.

**Executes.** Only on-board tools of the appliance: `sh`, `awk`, `grep`, `sed`, `perl`, `find`, `tar`, `gzip`, `sha256`, `ps`, `sockstat`, `netstat`, `sysctl`, `date`; no downloaded programs, no packages, no `eval` of file contents. The rules file is sourced; therefore a permission check (not group or world writable) before loading and a lint that rejects shell constructs in it. The custom file is not sourced, only read line by line.

**Network.** No outbound connection, no DNS query, no upload. The script checks connections, it does not open any.

**Credentials.** The CLI layer uses the service user from `ns_snapshot.conf` if the snapshot runs, otherwise from `ns_quickcheck.conf` (both root-owned, 600). Known weakness: `nscli -U %%:user:password` passes the password as an argument; it is visible in the process list for the duration of the command (seconds). Hence a dedicated service user with a read-only command policy, never `nsroot`; `cli_script.sh` without a password where available. Reports contain no passwords or hashes; the config diff masks them.

**Data in the output.** Original report and JSON contain host names, internal addresses, object names, log lines with user names and, since 17.25, the account names from failed gateway logons (personal data): internal to the operator, retention according to your own policy, `REPORT_KEEP_DAYS` deletes after 30 days. The anon versions replace what is in `ns.conf` or private, nothing more. Only anon versions leave the organization, after a spot check (5.3).

**Traceability.** Every RESULT line carries the SHA-256 of script, rules file and custom file; the operator can verify that what ran is what was approved. Runtime 5 to 30 seconds, brief CPU load, no impact on traffic; for very large access logs `ACCESS_LOG_MAX_MB` limits the amount read.

**What remains to consider.** A script that runs as root is a matter of trust: check the hash against the release page, file permissions 600, do not start it from a writable folder. The rules file is code (sourced); install it only from the release or after your own review. The custom file is not code, but it can make the assessment stricter; that is intended.

## 11. Runbook for an incident

Hash check of reported files: only look up the SHA-256 on VirusTotal, never upload the file (public, contains operator data).

1. Run the Quickcheck online with `--compare cron`; report and JSON in `/var/nssnapshot/quickcheck/`.
2. Read the verdict (section 7). `FORENSICS_FIRST` ends the patch plan, start the incident process. If it contains an AAA hit: first lock the account, reset the password, `kill aaa session -userName <account>`, then continue.
3. With `UPDATE`: back up, then patch. At least `show techsupport` and `/var/log` to external storage, if there are traces also `/var/core`.
4. HA pair: check both nodes; HA file sync copies webshells.
5. Upgrade: target build from block 1, secondary first, failover, primary. Then `save ns config`, `set ns tcpParam -enhancedISNGeneration ENABLED` in every partition, `save ns config -all`.
6. Follow-up: repeat the Quickcheck, verdict `OK` or `INVESTIGATE` without red. Address list to firewall and SOC.
7. Second opinion for an exposed appliance: community checkers and the official Citrix IoC scan (the "Indicators of Compromise" function of NetScaler Console, https://docs.netscaler.com/en-us/netscaler-console-service/instance-advisory/ioc; without Console via a support ticket).
8. Ticket: attach `_anon.txt` and `_anon.json`, put the RESULT line into the summary, name the rules version.

## 12. Limits and known weaknesses

| Item | Impact | Status |
|---|---|---|
| CLI layer only with a service user | without it: hit counters, deny list, sessions and diff between running and saved config are missing | set up the service user (3.1) |
| Time window based on file mtime | rotated logs older than the window are missing; large `httpaccess*` limited via `ACCESS_LOG_MAX_MB`; the source IP of an attempt is missing if the access log has rotated (the report says where it is in the snapshot set) | line filter by timestamp as a candidate |
| Source IP for a single attempt | offset search needs at least 2 attempts | stays, deliberately, to avoid false attribution |
| Block 5 finds only known patterns | an empty block 5 is not an acquittal | stays; hence runbook step 7 |
| Source IP attribution for logon lines is temporal proximity | an unrelated logon request in the same second can appear | stays; hence "passt zu n von m Versuchszeiten" and "schwach", never stated as fact. For responder lines only the address from the line |
| Conditions outside `ns.conf` and `tcpParam` | cannot be expressed as a rule, conservatively `all` | stays, changelog "Nicht abgebildet" (not covered) |
| `--compare` compares web files by mtime and size | whoever resets mtime is only caught by the hash | V18: hash comparison, cron, httpd.conf hash, SUID |
| Anonymization | only recognizes what is in `ns.conf` or private | stays; spot check before passing on |
| Custom file | can only make the assessment stricter and only contribute indicators and fix builds; check patterns only via ceterion | by design |
| Address list | contains observations, not assessments; NAT and CDN produce uninvolved parties | by design; note in the file header |
| `--ki-bundle` takes the two newest files per log | on quiet appliances sections stay empty | V18: older rotations |
| Thresholds in block 4 (4.3) | calibrated on a lab gateway; other environments need other values | config; false positive direction per threshold in 4.3 |
| Sleepers beyond the window (default 72 h, 168 h in the lab) | whoever pauses longer than the window is only caught via the cumulative address list | by design; never delete the list |
| Output in German only | report, terminal and finding texts in the JSON are German; field names, verdicts and RESULT are language-neutral | V18: message catalog and `--language en` |
| Webshell names with a variable number (Zscaler 2026-10-16: `Nx_<number>.php/.pl/.html` in six directories, the number differs per attack instance) | format 2 knows only exact values for `path`; the `.php` is caught by the generic check "PHP outside admin_ui" (red), `.pl` and `.html` only by "new web file since boot" (yellow) | V18: regex variable `WEBSHELL_NAME_RE`; until then exact paths (rules stand 2026-10-22b) |
| Shell logs (`bash.log`, `sh.log`) are not assessed | persistence via the shell goes undetected until rules exist | V18, rule draft first |

Done since v22: `--compare` no longer extracts to `/tmp` (17.3, own working directory with space check); reports are in archive 3 since snapshot V9; `EOL_RELEASES` is evaluated (17.4); IP indicators no longer match as substrings (17.0).

## 13. Testing (ceterion and power users)

Before every release `docs/release.sh` runs: copy check, platform lints (no `{ }` inside `$( )`, no `\t` in sed replacements, no intervals `{n,m}` in awk; `docs/PLATFORM.de.md`), format 2 lint, prefix check, provenance record, 54 test logs (`docs/testlogs/`, expectations in `expected.txt`, origin per line in `herkunft.md`), 6 fixtures (`clean`, `compromised`, `eol`, `custom`, `blocked`, `nologs`; expectations including RESULT fields in `fixture-expected.txt`). Test logs and fixtures are constructed from published descriptions, addresses from RFC 5737; never copy them to an appliance.

## 14. Related repositories and contact

Questions and acceptance support: netscaler-integrity@ceterion.com. Security bugs in the script: security@ceterion.com (SECURITY.md), never as a public issue. False positives and missed indicators: open an issue with the anon report.

| Repository | Purpose |
|---|---|
| `netscaler-snapshot` | daily file snapshot per appliance (four archives, manifest with SHA-256, runtime state); since V9 archive 3 contains the Quickcheck reports |
| `netscaler-collector` | analysis of snapshot sets and reports across devices and time (PowerShell 7); own engine for the rules file according to `rules-format-2.md` |

## 15. FAQ

### Everything is yellow, what now

In this order; each step makes findings disappear without hiding anything:
1. Enter blocked addresses and networks in `ns_quickcheck.blocked_ips` (5.4): dropper, probe and injection download hosts become orange and no longer count.
2. Put confirmed theme files into the whitelist (howto below): block 5 becomes empty.
3. Admin networks into `MGMT_NET_RE` (4.2): management and SSH messages from your own workstations disappear, own addresses in failed logons are listed as internal.
4. `PROBE_LEVEL=info` if probes should only be counted.
5. Adjust the AAA thresholds (4.2) to your environment, after the account list in the original report has shown which "unklar" (unclear) cases were humans.

Whatever is still yellow after that is new or needs a decision; the verdict becomes `OK` as soon as only orange and INFO remain.

### Whom do I call

| Finding | Call |
|---|---|
| "unklar, ein Konto in kurzem Burst" (unclear, one account in a short burst) | the user of the account (listed in the original report): renew the client or the stored password |
| "Anmeldefehler von eigenen oder internen Adressen" (failed logons from own or internal addresses) | the owner of the system behind the address (`ns.conf` object or network plan): service account, monitoring, test |
| Brute force on one account | the account owner and the helpdesk: lock the account or change the password, check MFA, find out where the name is known from |
| Hit (red) | the incident process, not the user first: lock the account, end the sessions, then ask |
| Machines, networks, sleepers, probes | firewall and SOC with the address list; call nobody |

### Howto whitelist: exclude confirmed web files

File `ns_quickcheck.whitelist` next to the script (600), one rule per line `<type>:<regex>`, types `webfile`, `user`, `listener`, `path`, `cron`. The regex is POSIX ERE and is matched against the full path.

```
# theme customization 2026-10-15, ticket CHG-1234: the theme folders and the favicons
webfile:^/var/netscaler/logon/themes/MeinTheme/
webfile:^/var/netscaler/logon/themes/MeinTheme_2025/
webfile:/images/common/favicon\.ico$
webfile:^/var/netscaler/gui/admin_ui/common/images/favicon\.ico$
```

Rules: keep paths as narrow as possible (one theme folder, not `/var/netscaler/logon/`), escape dots (`\.`), put a comment with date and ticket above. Run once after the change; the header line shows `Whitelist: ... (4 Regeln)`, and the files no longer appear in block 5. A whitelist rule removes the file from the change check, not from the webshell and PHP check; a `.php` in the theme folder stays red. The whitelist is kept on update, applies per appliance and is never distributed.

### Howto responder source: client address in the responder line

A responder policy that rejects the injection attempt stops the request in the Packet Engine; it never reaches the web server and appears in no access log. Then only the policy itself knows the source. By default the responder logs only the policy name; with an audit message action it writes client address, host header and request into the syslog line, and the script reads the source directly from it ("Quelle: ... (aus der Responder-Zeile)", source from the responder line).

```
add audit messageaction am_rs_badrequest WARNING "\"Bad Request (\" + HTTP.REQ.HOSTNAME + \" - \" + \"<policyname>\" + \") from IP \" + CLIENT.IP.SRC + \" - Hostname: \" + HTTP.REQ.HOSTNAME + \" - URL: \" + HTTP.REQ.URL.PATH_AND_QUERY + \" (headers: \" + HTTP.REQ.FULL_HEADER + \")\"" -logtoNewnslog YES
set responder policy <policyname> -logAction am_rs_badrequest
save ns config
```

Adapt the expression to your own policy; what matters is `from IP ` followed by `CLIENT.IP.SRC`. Note: `HTTP.REQ.FULL_HEADER` writes the complete request header to syslog, including cookies and authorization headers; if you do not want that, use `HTTP.REQ.HEADER("User-Agent")`. The line becomes long; `LINE_MAX` in the config does not apply to injection lines, they always appear in full in the report. The host header (the address under which the attacker contacted the gateway) is masked in the anon version unless it is a known attacker value.

### Howto lockout: lock accounts after failed attempts

The appliance can lock accounts for a period after a number of failed attempts (Citrix documentation "User account and password management", section "Configure lockout"):

```
set aaa parameter -maxloginAttempts 5 -failedLoginTimeout 15 -persistentLoginAttempts ENABLED
show aaa parameter
unlock aaa user <account>
```

`maxloginAttempts` counts failed attempts per account, `failedLoginTimeout` is the lockout duration in minutes, `persistentLoginAttempts ENABLED` keeps the counter across sessions and reboots. What it does and does not achieve: against brute force on one account it works immediately, after five attempts it stops. Against password spraying it does not work, because one attempt per account stays below any threshold; only a network block at the firewall and MFA help there. And it has a downside: whoever knows the account name can lock the account with five wrong passwords; for administrator accounts on the gateway therefore only with MFA and a second way in (console, management network). From build 13.1 on, the parameter applies to system accounts and external accounts; check details and version levels in the Citrix documentation.

### Howto field finding: your own address in the custom file

File `ns_quickcheck.rules.custom` next to the rules file (template `ns_quickcheck.rules.custom.example`). Insert one line before the closing marker `IOC`, fields separated by tabs:

```
ip	203.0.113.11	betreiber	2026-10-19	c	own access log, dropper search 17 to 19 Oct	betreiber-2026-10-21
```

Fields: type (`ip`, `dom`, `hash`, `path`), value, source (`betreiber`, operator), date of the observation, class `c`, source reference (where you know it from, without names), version. Then set `CUSTOM_VERSION` in the file to the date and run once; the header line shows the new line count. From now on every appliance with this custom file reports red as soon as the address appears in logs, connections or requests, with "Quelle: betreiber". If you do not want to edit the file: create a patch with an `IOC:` line and run `sh docs/rules-apply.sh ns_quickcheck.rules.custom <patch>` (WORKFLOW step 3); this checks format and duplicates.

A field finding never belongs in an issue (the address is your finding, the source reference is your log); if a publisher names it later, it reaches everyone via the rules file.

**Red although the build is fixed?** Red in block 4 on a fixed build means: someone tried, the attempt could not take effect. The detail lines say what to check (firewall log for the download host, access log for the source). The verdict is then `INVESTIGATE`, not `FORENSICS_FIRST`.

**The same yellow every day?** Usually "Web-Dateien seit Boot geändert" (web files changed since boot) after a theme customization. Check the date against the ticket, then enter the paths in `ns_quickcheck.whitelist` as `webfile:<regex>`; the message disappears.

**What may I pass on?** Only `_anon.txt`, `_anon.json` and, after review, `_ips.tsv`. Never the original, never the mapping table, never the custom file, never a bundle without anonymization.

**Custom file is not loaded?** `ls -l`: name exactly `ns_quickcheck.rules.custom`, in the folder of the rules file, permissions 600. The header line "Custom-Datei des Betreibers geladen" (operator custom file loaded) confirms it; `custom=none` in RESULT means it was not seen.

**`--compare` reports "filesystem is full"?** Script older than 17.3; it extracted to `/tmp` on the small root file system. Update, then `rm -rf /tmp/qc.*`.

**Why is the source IP of an attempt missing?** It is only in the access log, and that had rotated for the time in question. The snapshot set of the following day contains it; the report names the time to search for.

**Mapping table deleted, what happens?** The next run assigns new substitute names. Old and new anon reports then no longer match each other; nothing else.

**Can I approve the script in the change process?** It changes nothing on the appliance and writes only to its own directories (section 10): no change to the appliance, no network connection, no data transfer; it writes reports to `/var/nssnapshot/quickcheck/` and a mapping table next to the rules file. Runtime 5 to 30 seconds.

## 16. Glossary

| Term | Meaning |
|---|---|
| NSIP, SNIP, VIP | management address of the appliance; subnet address for backend traffic; address of a vServer |
| Packet Engine (PPE) | the appliance process that handles network traffic; `0-PPE-0` to `0-PPE-3` in log lines are the individual engines, a wave across all engines is an attack that arrived in parallel |
| `127.0.0.2` in the web server log | the appliance itself. The Packet Engine accepts gateway connections; whatever has to go to the web server (logon page, themes, EPA) it forwards internally via loopback. The web server therefore always sees `127.0.0.2` as the client, never the user or attacker. The real address is in the access log at the same time. A different client address in the web server log means direct access bypassing the gateway, usually via the NSIP |
| SAML SP, IdP | NetScaler as service provider (accepts logons from an IdP) or as identity provider; CVE-2026-88779 and 107406 affect SAML configurations only |
| DTLS | UDP variant of TLS, used by Gateway for EDT; prerequisite for CVE-2026-88772 |
| Enhanced ISN Generation | TCP parameter that CTX697096 requires for CVE-2026-88778; must be set after the upgrade |
| Responder policy, mitigation | rule that rejects requests before logon; Citrix workaround until the patch |
| Injection, log poisoning | attack via the logon field that writes commands into log lines which are executed later (CVE-2026-88771) |
| Payload, download host | the attacker's script or program loaded afterwards; the address it is fetched from |
| Dropper | package disguised as a Linux client that delivers the actual malware (`nsg64.deb` and similar) |
| Webshell | file in the web directory through which an attacker executes commands |
| nsaaad | authentication service of the appliance; its crash is a sign of attack with SAML on a vulnerable build |
| Snapshot set | the four archives of a snapshot run (config, file system, logs, runtime) with manifest |
| Fixture, test log | constructed test data in the repo, used to test script and rules before every release |
| Source reference, original publisher | the publication in which an indicator first appeared; only that counts as a source |
| Password spraying | few passwords against many accounts, usually one attempt per account, below any lockout threshold; countermeasures: network block and MFA |
| Brute force | many passwords against one account; countermeasures: lockout and locking the account |
| Sleeper | spraying so slow that rate and account thresholds do not trigger; detectable only over days |
| Machine, user, unclear | assessment of an address with failed logons by rate, accounts, network and success afterwards (4.3); in the output "Maschine", "Nutzer", "unklar" |
| Hit | successful logon after a failure series; sign of compromise until a human establishes otherwise |
| Orange, covered | finding for an address that according to the blocklist was blocked before the observation; does not count as a trace |
| `coverage` | `full` or `partial` in RESULT: whether every core check had data; `partial` prevents `OK` |
| Defanged | URLs written as `hxxp` so they are not clickable; addresses are unmasked since 17.18 |

## 17. README changelog

| Version | Date | Change |
|---|---|---|
| v25 (English draft) | 2026-10-22 | English translation of v25; script output stays German (language note at the top); section 7.1: `INVESTIGATE` with "Nicht vollständig geprüft" for `coverage=partial` restated; option `--conf`: `HOURS` added to the parameter list |
| v26 en | 2026-10-22 | English edition of v26: quick start to `/var/nssnapshot/`, 8.7 without naming individual community tools, rules stand 2026-10-22b |
| v25 | 2026-10-22 | Corrections after review: blocklist 5.4 reduced to three fields, `--hours` default 72 (plus `HOURS` in 4.2), `webshell_hit` in 5.2, eleven columns of the cumulative list, verdict rules moved to 7.1, service user sources in 4.2 and 10 |
| v24 | 2026-10-21 | For script 17.29 and rules version 2026-10-21d: logs read (3), configuration (4.2) and thresholds (4.3) as tables, block 4 in four groups with the AAA findings (hit, brute force, sleeper, spraying, internal), `coverage`, blocklist, address list with 11 columns, howtos responder source and lockout, FAQ "Everything is yellow" and "Whom do I call", glossary |
| v23 | 2026-10-21 | Rewritten for script 17.9: title, sections from 1, complete option table, security considerations, quick start, verdict decision table, address list, anonymization, provenance record, custom file, JSON, FAQ, glossary, limits cleaned up, section numbers cleaned up |
| v22 | 2026-10-20 | Verdict terms `UPDATE`, `INVESTIGATE` |
| v21 | 2026-10-15 | Script V15, release structure |
| v5 to v20 | 2026-10-08 to 10-14 | Development versions, see CHANGELOG.md |
