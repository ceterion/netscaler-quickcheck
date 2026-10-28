# Rules file format 2

Binding description of `ns_quickcheck.rules` from script V16 on and of the custom file from V17 (format version 1.3, 2026-10-21: variable groups and `RULES_MIN`).8 on. Two consumers read the file: the script on the appliance (POSIX sh, FreeBSD `awk` and `grep -E`) and the Collector (PowerShell 7, own engine). Both must evaluate every rule identically, which is why the language of the file is deliberately small. `docs/rules-apply.sh` and `docs/release.sh` lint these rules; the Collector checks them again when loading.

## Structure

- Only assignments `VAR='...'` or `VAR="..."` at the start of a line, comments starting with `#`, blank lines, and exactly one IOC block.
- The IOC block sits between a line `: <<'IOC'` and a line `IOC`. It is a here-document, so the shell never executes it; the script reads it with `awk`.
- IOC lines: `type<TAB>value<TAB>source<TAB>date<TAB>class<TAB>reference<TAB>rulesstate` (seven tab-separated fields). `type` is `ip`, `dom`, `hash` or `path`. `reference` is the URL or section of the original publisher; a line whose reference contains `PRUEFEN` or `ENTFERNEN` is inactive. `date` is the publication date at the original publisher, ISO format. `rulesstate` is the `RULES_VERSION` (or `CUSTOM_VERSION`) that added the line.
- `CVE_TABLE` rows: `CTX::CVE::train::fix::condition::text`, one per line inside the single-quoted value; condition is `all`, `conf:<ERE>` or `tcpparam:<flag>`.
- Multi-line values are allowed only inside single quotes (`CVE_TABLE`, `STOCK_FILE_HASHES`).

- Required variables: `RULES_VERSION`, `RULES_FORMAT="2"`, `TRIGGER_RE`, `OBFUSC_RE`, `CMD_NAMES`, `LOGON_HINT_RE`, `ADMIN_CMD_RE`, `CVE_TABLE` (not in a custom file, which has `CUSTOM_VERSION` and the IOC block only).
- IOC values: `ip` as `a.b.c.d`; `hash` 64 lowercase hex characters; `path` relative to `/` without `..`; `dom` only `[A-Za-z0-9.-]`.

## Variables the script expects

Core variables are mandatory; the script aborts with exit 3 if one is missing or empty: `RULES_VERSION`, `TRIGGER_RE`, `OBFUSC_RE`, `CMD_NAMES`, `LOGON_HINT_RE`, `ADMIN_CMD_RE`, `CVE_TABLE`.

Further variables by group; a missing one disables its check with an INFO line "not checked", and the report header notes when `RULES_VERSION` is older than the script's `RULES_MIN`:

| Group | Variables | Since |
|---|---|---|
| Bulletin traces | `NSAAAD_CRASH_RE`, `DTLS_FAIL_RE`, `PPE_CRASH_RE`, `LOGIN_PATH_RE`, `DROPPER_PATH_RE`, `MITIGATION_RULE_RE`, `EOL_RELEASES`, `BUILD_WARN_*` | Format 2 |
| Block 5 | `PAYLOAD_PATHS`, `STOCK_ALIAS_ROOTS`, `ALLOWED_CRON_RE`, `KNOWN_LISTENER_RE`, `SUSPECT_PROC_RE`, `SUSPECT_PROC_PARENT_OK_RE`, `STOCK_FILE_HASHES` | Format 2 |
| Web server and access logs | `HTTPERR_EXEC_RE`, `HTTPERR_PROBE_RE`, `AUTH_LOGIN_RE`, `AUTH_FAIL_RE`, `MGMT_PATH_RE` | 2026-10-21b |
| Gateway accounts (AAA) | `AAA_FAIL_RE`, `AAA_OK_RE` | 2026-10-21c, 2026-10-21d |

`RULES_VERSION` is a date `YYYY-MM-DD` with an optional letter suffix for several stands on one day (`2026-10-21d`); the script compares stands as strings, so the suffix must sort after the bare date.

## Custom file (`ns_quickcheck.rules.custom`)

The operator's file next to the rules file. It contains exactly: comments, `CUSTOM_VERSION="..."`, one IOC block (`: <<'IOC'` ... `IOC`, same columns as above, the seventh column being the custom version) and optionally one CVE block (`: <<'CVE'` ... `CVE`) with rows in the `CVE_TABLE` format `CTX::CVE::train::fix::condition::text`. Nothing else is read. Both consumers evaluate the custom rows in addition to the rules file: a row identical in CTX, CVE, train, fix and condition is evaluated once; a differing row is evaluated as well, and the stricter result decides the verdict. Custom rows never replace rules-file rows. `EOL_RELEASES` and all pattern variables exist only in the rules file.

## Quoting

- Inside `"..."` only the escapes `\$`, `\"`, `\\` and `` \` `` are allowed. No variables, no `$(...)`, no backticks, no process substitution.
- Inside `'...'` no single quote may appear.

## Regular expressions

- POSIX ERE as understood by FreeBSD `grep -E` and `awk`. Semantics is always "line matches: yes/no"; never match length or position.
- Character classes only as `[:space:]`, `[:digit:]`, `[:alpha:]`, `[:alnum:]`, `[:upper:]`, `[:lower:]`, `[:xdigit:]`, `[:blank:]`, `[:punct:]`, inside a bracket expression.
- Forbidden: backslash inside a bracket expression (`[\.]`), GNU extensions `\<`, `\>`, `\b`, `\B`, `\w`, `\W`, `\s`, `\S`, `\d`, `\D`, back-references `\1` to `\9`, lazy quantifiers, lookaround, `(?i)` flags.
- Case-insensitivity is a property of the check, not of the pattern: conditions in `CVE_TABLE` are evaluated with `grep -iE`; log patterns are evaluated as written. The rules changelog states which check is case-insensitive.
- IP values in IOC lines are plain dotted quads; the script adds the boundaries `(^|[^0-9.])` and `([^0-9.]|$)` itself. Domain values are plain names; the script escapes the dots and adds the boundaries `(^|[^A-Za-z0-9-])` and `([^A-Za-z0-9.-]|$)`, so a subdomain of the indicator matches and a longer name that merely contains it does not; the comparison is case-insensitive. Do not pre-escape values.

## Lint (rules-apply.sh and release.sh)

Rejects a file or patch when: a line is neither assignment, comment, blank nor inside the IOC block; a double-quoted value contains `$(`, a backtick or an unescaped `$`; a regex value contains `\<`, `\>`, `\b`, `\w`, `\s`, `\d`, a back-reference or a backslash inside brackets; an IOC line has fewer than six fields or an empty reference; an IOC `type`+`value` pair appears twice.

## Changelog

- 1.2 2026-10-21 custom file with IOC and optional CVE block, both evaluated additively, stricter result decides
- 1.1 2026-10-20 required variables, `[:punct:]`, uppercase GNU classes, IOC value formats, EOL fixture (Collector-chat handover)
- 1.0 2026-10-20 first version, from the Collector-chat handover (96 of 96 prototype cells identical to `--testlog`)

## 1.4 (2026-10-28): fix build `pending`

A `CVE_TABLE` row may carry `pending` instead of a fix build: `CTX697263::CVE-2026-109618::14.1::pending::all::...`. It means the vendor has published the advisory but no fixed build yet. Scripts from 17.37 rate every build of that train as vulnerable and say "kein Fix-Build veroeffentlicht (Stand <rules version>)"; older scripts skip the row with a SKIP line. `rules-apply.sh` 2.5 accepts the value. Fix builds themselves come only from the CTX article, section "What Customers Should Do"; never from blogs or from the overview of another bulletin.
