# Report format (script 17.29)

Binding description of what `ns_quickcheck.sh` writes per run, for the Collector and anyone reading reports by machine. German text in the report is data; field names are stable.

## Files per run

| File | Content |
|---|---|
| `ns_quickcheck_<host>_<ts>.txt` | the report as printed; last line is `RESULT ...` |
| `ns_quickcheck_<host>_<ts>.json` | structured copy (below) |
| `ns_quickcheck_<host>_<ts>_ips.tsv` | foreign addresses of this run, one line per category and address |
| `ns_quickcheck_observed_ips.tsv` | cumulative address list of the appliance, kept across runs |
| `ns_quickcheck_<alias>_<ts>_anon.txt`, `_anon.json` | anonymized copies; `<alias>` is the mapped host name |

`<ts>` is `YYYYMMDD_HHMMSS` in appliance local time.

## RESULT line

Space-separated `key=value`, one line, always last in the report:

| Key | Values | Meaning |
|---|---|---|
| `host`, `build`, `mode`, `cli`, `window` | text | appliance, build string, `online` or `offline`, `nscli` or `none`, log window in hours (`168h`) |
| `saml`, `vuln96`, `vuln63`, `vuln79`, `isn_open` | 0 or 1 | SAML configured; a CTX697096 CVE open (since 17.38 strictly CTX697096; before, any open CVE); a CTX697263 (PHP2Shell) CVE open; a SAML CVE open; Enhanced ISN missing |
| `vuln_open` | integer | number of open CVE rows across all bulletins (17.38) |
| `traces`, `mitigation`, `unsaved`, `save_missing`, `compromise` | 0 or 1 | attack traces found; mitigation policy bound; unsaved config lines; `save ns config` missing; compromise indicator found |
| `red`, `yellow`, `orange` | integer | finding counts by colour; orange = covered by the operator's block list |
| `blocked_seen` | integer | blocked addresses observed in this run |
| `crashes` | integer | crash events in the window (Pitboss, kernel, Apache error log, core files), one per process and PID (17.41) |
| `trusted_seen` | integer | trusted addresses (trusted list) active in this run, each reported as `[TRUST]` |
| `coverage` | `full`, `partial` | whether every core check had data; `partial` never yields `OK` |
| `action` | `OK`, `UPDATE`, `INVESTIGATE`, `FORENSICS_FIRST` | verdict; exit code 0 for `OK`, 1 for `INVESTIGATE`, 2 for `UPDATE` and `FORENSICS_FIRST`; exit 3 means the run aborted before a verdict (rules file or core variable missing, option without value) and no `RESULT` line is written |
| `rules`, `custom` | stand | `RULES_VERSION`; `CUSTOM_VERSION` or `none` |
| `script_sha256`, `rules_sha256`, `custom_sha256` | hex | hashes of what ran |
| `cve_custom`, `cve_conflict` | integer | CVE lines from the custom file; lines that diverge from the rules file |
| `runtime` | seconds | wall time |

## JSON

```
{ "script": "ns_quickcheck", "version": "17.29", "host": "...", "ts": "...",
  "result": { all RESULT keys as strings },
  "mitigation_hits": { "<policy>": "<hits>" },
  "observed_ips": [ { "category": "...", "ip": "...", "count": n, "observed_in": "...", "blocked": "<remark>|<since>" or "" } ],
  "red":    [ { "text": "...", "details": [ "..." ] } ],
  "yellow": [ { "text": "...", "details": [ "..." ] } ],
  "orange": [ { "text": "...", "details": [ "..." ] } ],
  "trust":  [ { "text": "...", "details": [ "..." ] } ],
  "source_url": "https://ceterion.com/netscaler-quickcheck" }
```

Finding `text` is the headline as printed (without the colour tag); `details` are the indented `|` lines in order. URLs are defanged (`hxxp`); addresses are not.

## Address lists

Per-run file: tab-separated `category`, `ip`, `count`, `observed_in`, `blocked` (`<remark>|<since>` or empty). Header lines start with `#`.

Cumulative file, 11 tab-separated columns: `category`, `ip`, `count_last`, `last_window_h`, `count_max`, `max_window_h`, `days`, `first_seen`, `last_seen`, `observed_in`, `blocked`. `days` counts calendar days on which a run saw the address (several runs on one day count once); counts are per run and never summed, because every run reads the same logs again.

Categories: `payload_download_host`, `injection_source`, `injection_source_candidate`, `dropper_requester`, `outbound_hit`, `webshell_probe`, `webshell_hit`, `webserver_direct`, `mgmt_access`, `ssh_login_external`, `ssh_bruteforce`, `aaa_bruteforce`, `aaa_sleeper`, `aaa_hit`. `crash_trigger`: address whose request preceded a process crash by at most 120 seconds (17.41). Addresses from the trusted list appear with the prefix `trusted_` (for example `trusted_webshell_probe`); the import command in the file header excludes them. Own, RFC 1918 and `MGMT_NET_RE` addresses never appear.

## Verdict rules

1. `FORENSICS_FIRST` if `compromise=1`.
2. `UPDATE` if a CVE is open or the train is end-of-life and no traces.
3. `INVESTIGATE` if traces without bound mitigation, any yellow finding, Enhanced ISN missing, or `coverage=partial`.
4. `OK` otherwise; orange findings alone keep `OK`.

## Compatibility

Keys are only added, never renamed. A consumer must ignore unknown keys and categories. Changes are listed in `CHANGELOG.md` under the script version.

## Anonymized lists and share file (17.32)

`ns_quickcheck_<anonhost>_<ts>_ips_anon.tsv` and `ns_quickcheck_observed_ips_anon.tsv`: same columns as the originals, host name replaced, remarks of the block and trusted lists removed (`gesperrt` keeps only the date, `(trusted ...)` keeps only the expiry), mapping table applied. `ns_quickcheck_<anonhost>_<ts>_share.tsv`: `kategorie`, `ip`, `zuerst`, `zuletzt`, `tage`, `anzahl_max`, `max_fenster_h`, `anzahl_zuletzt`, `regeldatei` (ja/nein); only `payload_download_host`, `injection_source`, `webshell_hit`, `outbound_hit`, `aaa_bruteforce`, `aaa_maschine`, `aaa_hit`, `ssh_bruteforce` and `dropper_requester` with `anzahl_max` >= 3; no `trusted_*`, no probing categories, no appliance identifier.
