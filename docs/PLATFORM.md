# Platform notes: NetScaler /bin/sh

Deutsch mit allen Details: [PLATFORM.de.md](PLATFORM.de.md).

- The NetScaler `/bin/sh` (FreeBSD-based, 13.1 and 14.1) crashes with a segmentation fault on any brace group inside a command substitution: `$( { ...; } | ... )`, `$(a | { ...; } | b)`. Never write that construct; `docs/release.sh` lints for it.
- The FreeBSD `awk` (BWK) does not support interval expressions `{n,m}` in regular expressions; `[0-9]{1,2}` never matches. Use `+`, `*`, `?` or spelled-out repetitions in awk, and perl for date parsing; `docs/release.sh` lints for it. Intervals are fine in `grep -E` and perl.
- The FreeBSD `sed` does not understand `\t` in patterns or replacements (it writes a literal `t`); GNU sed on a workstation hides this. Produce tabs with `awk` or `printf`, never with `sed`; `docs/release.sh` lints for it.
- Only POSIX sh, FreeBSD `awk`, `grep -E`, `sed`, `perl` and the tools listed in the README, section 10, are used. No bashisms, no process substitution, no GNU regex extensions.
- `/tmp` sits on the small root file system; all temporary work goes to `$BASE_DIR/tmp` (default `/var/nssnapshot/tmp`).
- `nscli -U %%:user:password` exposes the password in the process list for the duration of the command; use a read-only service user, never nsroot.
- The rules file is sourced by the shell; the custom file is only parsed line by line. Both must be mode 600 and not group/world-writable, or they are refused.
