#!/bin/sh
# release.sh - erzeugt die unversionierte Kopie des Scripts aus der versionierten Quelle und prueft den Gleichlauf.
# Nur das Script bekommt eine Kopie (operative Arbeit auf der Appliance); Markdown-Dateien bleiben versioniert.
# Quelle ist immer die versionierte Datei; die Kopie wird ueberschrieben. Vor jedem Commit ausfuehren.
# Copyright 2026 ceterion AG. SPDX-License-Identifier: Apache-2.0. Provided "AS IS".
set -e
cd "$(dirname "$0")/.."
pairs="ns_quickcheck_V18.sh:ns_quickcheck.sh"
rc=0
echo "$pairs" | while IFS=: read -r src dst; do
  [ -f "$src" ] || { echo "FEHLT: $src" >&2; exit 1; }
  if [ -f "$dst" ] && ! cmp -s "$src" "$dst"; then echo "AKTUALISIERT: $dst aus $src"; fi
  cp "$src" "$dst"
done
# Gleichlauf pruefen
echo "$pairs" | while IFS=: read -r src dst; do cmp -s "$src" "$dst" || { echo "ABWEICHUNG: $src $dst" >&2; exit 1; }; done
echo "release.sh: Kopien aktuell"
rm -f ns_quickcheck.anon.*.map 2>/dev/null   # Zuordnungstabellen aus Testlaeufen gehoeren nicht ins Repo
# liegengebliebene Laufdateien im Baum (Reports, Adresslisten, Zuordnungstabellen) duerfen nicht ins Paket
_stray=$(find . -maxdepth 2 -not -path "./docs/testdata/reference/*" \( -name 'ns_quickcheck_*_20*' -o -name '*_ips.tsv' -o -name 'ns_quickcheck_observed_ips.tsv' -o -name 'ns_quickcheck.anon.*.map' \) 2>/dev/null | grep -v '^./docs/testdata/' || true)
[ -z "$_stray" ] || { echo "release.sh: FAIL: Laufdateien im Baum: $_stray" >&2; exit 1; }
# Release-Notes: docs/releases/v<version>.md muss existieren und die Hashes beider Assets nennen
_v=$(grep -m1 '^VERSION=' ns_quickcheck.sh | sed 's/VERSION="\([0-9.]*\)".*/\1/'); _rn="docs/releases/v$_v.md"
[ -f "$_rn" ] || { echo "release.sh: FAIL: $_rn fehlt" >&2; exit 1; }
_hs=$(sha256sum ns_quickcheck.sh | cut -c1-64); _hr=$(sha256sum ns_quickcheck.rules | cut -c1-64)
grep -q "$_hs" "$_rn" || { echo "release.sh: FAIL: $_rn nennt nicht den Hash von ns_quickcheck.sh ($_hs)" >&2; exit 1; }
grep -q "$_hr" "$_rn" || { echo "release.sh: FAIL: $_rn nennt nicht den Hash von ns_quickcheck.rules ($_hr)" >&2; exit 1; }
# Plattform-Lint 4: BWK-awk kennt keine GNU-Funktionen (strftime, systime, gensub, asort, mktime)
perl -ne 'next if /^\s*#/; if (/awk\b/ && /'"'"'(.*?)'"'"'/s) { my $p=$1; if ($p =~ /\b(strftime|systime|gensub|asorti?|mktime)\s*\(/) { print "$.: $_"; $bad=1 } } END { exit($bad?1:0) }' ns_quickcheck.sh || { echo "release.sh: Plattform-Lint FAIL: GNU-awk-Funktion in awk-Programm (BWK-awk)" >&2; exit 1; }
# Plattform-Lint 5: Werkzeuge, die auf der Appliance fehlen (comm, timeout, seq ist da; GNU-Optionen von date/stat/readlink)
perl -ne 'next if /^\s*#/; if (/(^|[;|&(\s])(comm|timeout|realpath|tac|shuf|nproc)\s/ || /\bdate -d\b/ || /\bstat -c\b/ || /\breadlink -f\b/ || /\bsed -i\b/) { print "$.: $_"; $bad=1 } END { exit($bad?1:0) }' ns_quickcheck.sh || { echo "release.sh: Plattform-Lint FAIL: Werkzeug oder GNU-Option, die auf der Appliance fehlt" >&2; exit 1; }
# Plattform-Lint 6: Anfuehrungszeichen oder Klammern in ${...}-Mustern; an einer solchen Zeile stuerzte der Parser der FreeBSD-sh ab
# (Lab 04.11.2026). Schleifen in $( ) sind dagegen unkritisch (seit 17.x im Einsatz), die Ursache des dritten Crashs blieb ungeklaert.
perl -ne 'next if /^\s*#/; if (/\$\{[A-Za-z_][A-Za-z0-9_]*[#%]{1,2}[^}]*["()]/) { print "$.: Anfuehrungszeichen/Klammer im \${}-Muster: $_"; $bad=1 } END { exit($bad?1:0) }' ns_quickcheck.sh || { echo "release.sh: Plattform-Lint FAIL: Muster in \${} mit Anfuehrungszeichen oder Klammer" >&2; exit 1; }
# Kundendaten-Lint (18.1): oeffentliche Adressen und Kontonamen ausserhalb der Fixture- und Dokumentationsmuster in Script,
# Katalogen, Hauptdoku und Release-Notes (nicht in Regeldatei, Provenance und Regel-Changelog: dort stehen Indikatoren).
# Treffer heisst anschauen, nicht automatisch loeschen. Ausnahmen in docs/tools/lint_allow.txt (eine Zeichenfolge je Zeile).
_lint_files="ns_quickcheck.sh ns_quickcheck.msg.de ns_quickcheck.msg.en README.md README.de.md WORKFLOW.md WORKFLOW.de.md SECURITY.md ns_quickcheck_README.md ns_quickcheck_README.en.md CHANGELOG.md CHANGELOG.de.md docs/report-format.md $(ls docs/releases/*.md 2>/dev/null | tr '\n' ' ')"
_lint_hits=$(grep -ohE '\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b' $_lint_files 2>/dev/null | sort -u \
  | grep -vE '^(203\.0\.113\.|198\.51\.100\.|192\.0\.2\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|0\.0\.0\.0|255\.|224\.0\.0\.|[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,3}\.[0-9]{1,3}$)' \
  | grep -vxFf docs/tools/lint_allow.txt || true)
_lint_names=$(grep -ohE '\b(user[a-z]*[0-9]{2,}[a-z]*|victim[0-9]+|[A-Za-z]+\.\.[a-z]+|up[0-9]{4,})\b' ns_quickcheck.sh ns_quickcheck.msg.de ns_quickcheck.msg.en $(ls docs/releases/*.md 2>/dev/null) 2>/dev/null | sort -u | grep -vE '^(user[0-9]{2,3}|victim[0-9]{2})$' | grep -vxFf docs/tools/lint_allow.txt || true)
if [ -n "$_lint_hits" ] || [ -n "$_lint_names" ]; then echo "release.sh: Kundendaten-Lint: pruefen (Adressen oder Namen ausserhalb der Fixture-Muster):" >&2; printf '%s\n%s\n' "$_lint_hits" "$_lint_names" | grep . | sed 's/^/  /' >&2; exit 1; fi
# Testdaten-Lint (18.8): oeffentliche IPv4-Adressen in Testlogs und Fixtures nur aus den Dokumentationsnetzen (RFC 5737, RFC 6598)
# oder als Indikator in der Regeldatei (veroeffentlichte IoCs); alles andere stammt aus Betreiber-Logs und ist ein Baufehler (FAIL).
_td_hits=$(grep -rhoE '\b([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\b' docs/testlogs docs/testdata 2>/dev/null | sort -u | awk -F. '
  $1>255||$2>255||$3>255||$4>255 { next }
  $1==10 || ($1==172 && $2>=16 && $2<=31) || ($1==192 && $2==168) || $1==127 || $1==0 || ($1==169 && $2==254) || $1>=224 { next }
  ($1==192 && $2==0 && $3==2) || ($1==198 && $2==51 && $3==100) || ($1==203 && $2==0 && $3==113) || ($1==100 && $2>=64 && $2<=127) { next }
  { print }' | while read -r _ip; do grep -qF "$_ip" ns_quickcheck.rules || echo "$_ip"; done)
[ -z "$_td_hits" ] || { echo "release.sh: FAIL: Testdaten-Lint: oeffentliche Adressen ausserhalb Dokumentationsnetze und Regeldatei in docs/testlogs oder docs/testdata:" >&2; echo "$_td_hits" | sed 's/^/  /' >&2; grep -rlF -f /dev/stdin docs/testlogs docs/testdata <<EOF2 | sed 's/^/  in: /' >&2
$_td_hits
EOF2
exit 1; }
# Versionsregel (18.2): jede Aenderung an Script, Regeldatei oder Katalog ergibt eine neue Versionsnummer. Release-Notes gelaufener Staende
# (Zeile "Status: gelaufen" oder "Status: gepusht" in docs/releases/v<version>.md) sind eingefroren: ihre vier Hashes muessen den Dateien entsprechen.
_sv=$(sed -n 's/^VERSION="\([0-9.]*\)".*/\1/p' ns_quickcheck.sh | head -1); _rn="docs/releases/v$_sv.md"
[ -f "$_rn" ] || { echo "release.sh: FAIL: $_rn fehlt (jede Version braucht Release-Notes)" >&2; exit 1; }
if grep -qE '^Status: (gelaufen|gepusht)' "$_rn"; then
  for _f in ns_quickcheck.sh ns_quickcheck.rules ns_quickcheck.msg.de ns_quickcheck.msg.en; do _h=$(sha256sum "$_f" | cut -c1-64)
    grep -q "| \`$_f\` | \`$_h\` |" "$_rn" || { echo "release.sh: FAIL: Version $_sv ist gelaufen oder gepusht ($_rn eingefroren), $_f weicht ab; Version hochzaehlen" >&2; exit 1; }; done
fi
# msg-percent (18.4): jede Vorlage beider Kataloge mit Werten, die %1..%9 und %2527 enthalten, durch msg() laufen lassen; Abbruch bei
# Wachstum (Endlosschleife) oder Verlust (%2527 muss erhalten bleiben). Laeuft in einer Subshell mit den Katalogfunktionen des Scripts.
for _cat in ns_quickcheck.msg.de ns_quickcheck.msg.en; do
  _mp_out=$(WORK=$(mktemp -d) sh -c '
    msg_load() { while IFS="$(printf "\t")" read -r k v; do case "$k" in ""|\#*) continue ;; esac; eval "MSG_$k=\"\$v\""; done < "$1"; }
    '"$(sed -n '/^msg() {$/,/^}/p' ns_quickcheck.sh)"'
    msg_load "'"$_cat"'"
    grep -vE "^(#|$)" "'"$_cat"'" | cut -f1 | while read -r k; do
      v=$(msg "$k" "a%2527%2522%1b" "c%2%3d" "e%9f" "g%4" "h%5" "i%6" "j%7" "k%8" "l%1")
      case "$v" in *"%2527%2522"*|*"["*"]"*) ;; *) t=$(eval "printf %s \"\${MSG_$k}\""); case "$t" in *%1*) echo "LOSS $k" ;; esac ;; esac
      [ ${#v} -gt 4000 ] && echo "GROWTH $k"
    done' 2>&1 | head -5)
  [ -z "$_mp_out" ] || { echo "release.sh: msg-percent FAIL ($_cat): $_mp_out" >&2; exit 1; }
done
# Config-Vorlage zweisprachig (18.5): vor jeder Parameterzeile genau zwei Kommentarzeilen (deutsch, englisch)
_cl=$(awk '/^#? ?[A-Z_]+=/ { if (!(p1 ~ /^# / && p2 ~ /^# /)) print NR": "$0 } { p2=p1; p1=$0 }' ns_quickcheck.conf.example)
[ -z "$_cl" ] || { echo "release.sh: FAIL: ns_quickcheck.conf.example: Parameter ohne zwei Kommentarzeilen (de, en):" >&2; echo "$_cl" | sed 's/^/  /' >&2; exit 1; }
# Sequenz (18.6): zwei Laeufe hintereinander mit --out (Vergleich, Kontendateien, kumulierte Listen, JSON mit code, anon-Fassungen)
sh docs/tools/refseq.sh check || exit 1
# Laufzeit (18.6): synthetische Fixture mit 2000 Adressen und 50.000 AAA-Zeilen; ueber PERF_MAX_S Sekunden ist ein FAIL
_pf=$(mktemp -d); sh docs/tools/genperf.sh "$_pf/fx" >/dev/null 2>&1; cp ns_quickcheck.rules "$_pf/r"; chmod 600 "$_pf/r"
_p0=$(date +%s); ( cd "$_pf" && sh "$OLDPWD/ns_quickcheck.sh" --from "$_pf/fx" --rules "$_pf/r" --hours 1000000 --out "$_pf/o.txt" >/dev/null 2>&1 ) || true; _p1=$(date +%s); rm -rf "$_pf"
echo "PERF: perf-2000 in $((_p1 - _p0))s (Grenze ${PERF_MAX_S:-120}s)"; [ $((_p1 - _p0)) -le "${PERF_MAX_S:-120}" ] || { echo "release.sh: FAIL: Laufzeit perf-2000 ueber der Grenze" >&2; exit 1; }
# umlaut-anon (18.6): Konto mit Umlaut darf in der anon-Fassung weder im Original noch in der gepunkteten Form stehen
_ua=$(mktemp -d); cp ns_quickcheck.rules "$_ua/r"; chmod 600 "$_ua/r"
( cd "$_ua" && sh "$OLDPWD/ns_quickcheck.sh" --from "$OLDPWD/docs/testdata/fixtures/umlaut-account" --rules "$_ua/r" --hours 1000000 --out "$_ua/u.txt" >/dev/null 2>&1 ) || true
if grep -aq 'm..ller\|M..ller' "$_ua"/*_anon.txt 2>/dev/null; then echo "release.sh: FAIL: umlaut-anon: Konto in der anon-Fassung lesbar" >&2; rm -rf "$_ua"; exit 1; fi; rm -rf "$_ua"
# Nachrichtenkataloge (18.0): gleiche Key-Mengen, gleiche Platzhalter je Key, jeder Key genau einmal, keine Gedankenstriche
_kt=$(mktemp -d)
for _c in ns_quickcheck.msg.*; do
  [ "$(grep -v '^#' "$_c" | cut -f1 | sort | uniq -d | wc -l)" -eq 0 ] || { echo "release.sh: FAIL: $_c hat doppelte Keys" >&2; exit 1; }
  perl -ne 'exit 1 if /\x{2013}|\x{2014}|\xe2\x80\x93|\xe2\x80\x94/' "$_c" || { echo "release.sh: FAIL: $_c enthaelt Gedankenstriche" >&2; exit 1; }
  grep -v '^#' "$_c" | sort | awk -F'\t' '{ n=gsub(/%[0-9]/,"",$2); print $1 "\t" n }' > "$_kt/$_c.keys"
done
for _c in ns_quickcheck.msg.*; do [ "$_c" = ns_quickcheck.msg.de ] && continue
  cmp -s "$_kt/ns_quickcheck.msg.de.keys" "$_kt/$_c.keys" || { echo "release.sh: FAIL: Keys oder Platzhalterzahl von ns_quickcheck.msg.de und $_c verschieden:" >&2; diff "$_kt/ns_quickcheck.msg.de.keys" "$_kt/$_c.keys" | head -5 >&2; exit 1; }
done; rm -rf "$_kt"
# Script ohne Satzliterale in Ausgabefunktionen (Detailpraefix erlaubt)
perl -ne 'next if /^\s*#/; while (/\b(out|inf|grn|flag_red|flag_yel|flag_org|flag_tru|hdr) "([^"\$]{4,})/g) { my $t=$2; next if $t =~ /^\s*\|?\s*$/; print "$.: $t\n"; $bad=1 } END { exit($bad?1:0) }' ns_quickcheck.sh || { echo "release.sh: FAIL: Satzliteral in Ausgabefunktion (gehoert in den Katalog)" >&2; exit 1; }
# Referenzreports: jede Fixture gegen docs/testdata/reference/<fixture>.<sprache>.txt (normalisiert); Abweichung = gewollte Aenderung mit docs/tools/refgen.sh nachziehen
. ./docs/tools/refnorm.sh; _rt=$(mktemp -d); _root=$(pwd)
for _ref in docs/testdata/reference/*.txt; do _fx=$(basename "$_ref" .txt); _lang=${_fx##*.}; _fx=${_fx%.*}; _d="$_root/docs/testdata/fixtures/$_fx"; [ -d "$_d" ] || continue
  _o="$_rt/$_fx.$_lang"; mkdir -p "$_o"; cp ns_quickcheck.rules "$_o/r"; chmod 600 "$_o/r"
  _extra=""; [ -f "$_d/blocked_ips" ] && _extra="$_extra --blocked $_d/blocked_ips"; [ -f "$_d/trusted_ips" ] && _extra="$_extra --trusted $_d/trusted_ips"; [ -f "$_d/ns_quickcheck.trusted_ips" ] && _extra="$_extra --trusted $_d/ns_quickcheck.trusted_ips"; [ -f "$_d/ns_quickcheck.blocked_ips" ] && _extra="$_extra --blocked $_d/ns_quickcheck.blocked_ips"; [ -f "$_d/ns_quickcheck.conf" ] && _extra="$_extra --conf $_d/ns_quickcheck.conf"; [ -f "$_d/whitelist" ] && _extra="$_extra --whitelist $_d/whitelist"
  _hours=1000000; [ -f "$_d/refgen.hours" ] && _hours=$(cat "$_d/refgen.hours"); _now=""; [ -f "$_d/refgen.now" ] && _now=$(cat "$_d/refgen.now")
  ( cd "$_o" && QC_NOW="$_now" sh "$_root/ns_quickcheck.sh" --from "$_d" --rules "$_o/r" --hours "$_hours" --out "$_o/report.txt" --lang "$_lang" $_extra >/dev/null 2>&1 ) || true
  refnorm "$_o/report.txt" "$_rt" > "$_o/norm.txt"
  if ! cmp -s "$_o/norm.txt" "$_ref"; then echo "release.sh: FAIL: Referenzreport $_fx ($_lang) weicht ab:" >&2; diff "$_o/norm.txt" "$_ref" | head -8 >&2; rm -rf "$_rt"; exit 1; fi
done; rm -rf "$_rt"; echo "REFERENZ: $(ls docs/testdata/reference/*.txt | wc -l | tr -d ' ') Reports identisch"
# Changelogs: beide Sprachen tragen denselben obersten Versionskopf
_hd=$(grep -m1 '^## v' CHANGELOG.de.md | cut -d' ' -f2); _he=$(grep -m1 '^## v' CHANGELOG.md | cut -d' ' -f2)
[ "$_hd" = "$_he" ] || { echo "release.sh: FAIL: CHANGELOG.de.md ($_hd) und CHANGELOG.md ($_he) haben verschiedene oberste Versionen" >&2; exit 1; }
# Changelog-Hash: der oberste Eintrag der Regel-Historie muss den Hash der aktuellen Regeldatei tragen
_h=$(sha256sum ns_quickcheck.rules | cut -c1-64); _c=$(grep -o 'Nachher:\*\* SHA-256 [0-9a-f]*' ns_quickcheck.rules.changelog.md | head -1 | awk '{print $3}')
[ "$_h" = "$_c" ] || { echo "release.sh: Changelog-Hash FAIL: ns_quickcheck.rules.changelog.md nennt $_c, Regeldatei hat $_h" >&2; exit 1; }
# Plattform-Lint 3: BWK-awk der Appliance kennt keine Intervalle {n,m} in regulaeren Ausdruecken; nur +, *, ? und ausgeschriebene Wiederholungen
perl -ne 'next if /^\s*#/; if (/awk\b/ && /'"'"'(.*?)'"'"'/s) { my $p=$1; if ($p =~ /\{\d+(,\d*)?\}/) { print "$.: $_"; $bad=1 } } END { exit($bad?1:0) }' ns_quickcheck.sh || { echo "release.sh: Plattform-Lint FAIL: Intervall {n,m} in awk-Programm (BWK-awk)" >&2; exit 1; }
# Plattform-Lint 2: BSD-sed kennt \t in Muster und Ersetzung nicht (schreibt ein t); awk oder printf verwenden
grep -vE "^[[:space:]]*#" ns_quickcheck.sh | grep -nE "sed[^|]*\\\\t" && { echo "release.sh: Plattform-Lint FAIL: sed mit \\t (BSD-sed), awk/printf verwenden" >&2; exit 1; }
# Plattform-Lint: Klammergruppe innerhalb einer Kommandosubstitution stuerzt die NetScaler-sh (SIGSEGV, 10.0 bis 12.0)
# Zeichenweise: Tiefe von $( ... ) verfolgen; eine oeffnende Klammergruppe bei Tiefe > 0 ist ein Treffer. Kommentarzeilen ausgenommen.
if awk '
  /^[[:space:]]*#/ { next }
  { d=0; q=0; hit=0; n=length($0)
    for (i=1; i<=n; i++) { c=substr($0,i,1); nx=substr($0,i+1,1)
      if (c=="\\") { i++; continue }
      if (c=="\047" && !q) { q=1; continue } else if (c=="\047" && q) { q=0; continue }
      if (q) continue
      if (c=="$" && nx=="(") { d++; i++; continue }
      if (c=="(" && d>0) { d++; continue }
      if (c==")" && d>0) { d--; continue }
      if (c=="{" && d>0 && (i==1 || substr($0,i-1,1) ~ /[ |(;]/)) { hit=1 }
    }
    if (hit) { print NR": "$0; bad=1 }
  }
  END { exit bad }' ns_quickcheck.sh; then :; else
  echo "release.sh: Klammergruppe in \$( ) gefunden, siehe docs/PLATFORM.de.md" >&2; exit 1
fi
sh -n ns_quickcheck.sh || exit 1
sh -n docs/rules-apply.sh || exit 1
# Funktions-Lint: jedes Ausgabewort am Satzanfang (nach then/else/;/do oder Zeilenbeginn) muss eine definierte Funktion sein
defs=$(grep -oE '^[a-z_]+\(\)' ns_quickcheck.sh | tr -d '()' | sort -u | tr '\n' '|' | sed 's/|$//')
if grep -nE '(^|then |else |; |do )(ok|okay|green|yellow|red_|info|warn|flag_green|flag_info|note) "' ns_quickcheck.sh | grep -vE "^[0-9]+:[[:space:]]*#" | grep -vE "(^|then |else |; |do )($defs) \"" ; then
  echo "release.sh: undefinierte Ausgabefunktion aufgerufen (siehe Zeilen oben)" >&2; exit 1
fi
# Regel-Muster gegen die Testlogs; ein FAIL blockiert den Commit
# Regeldatei-Pruefungen (Format 2): Kopfkommentar ohne Script-Version; jede IOC-Zeile 6 Felder mit Fundstelle; inaktive zaehlen
head -1 ns_quickcheck.rules | grep -q "_V[0-9]" && echo "WARN: Kopfkommentar der Regeldatei nennt eine Script-Version, veraltet bei jedem Sprung"
awk -F'\t' '/^: <<'"'"'IOC'"'"'$/ { f=1; next } /^IOC$/ { f=0 } f && !/^#/ && NF { n++; if (NF < 6 || $6 == "") { bad++; print "ERROR: IOC-Zeile ohne 6 Felder oder Fundstelle: " $0 } if ($6 ~ /PRUEFEN|ENTFERNEN/) ina++ } END { printf "IOC: %d Zeilen, %d inaktiv (PRUEFEN/ENTFERNEN)\n", n, ina+0; exit (bad ? 1 : 0) }' ns_quickcheck.rules || { echo "release.sh: IOC-Pruefung FAIL" >&2; exit 1; }
grep -qE "^(ATTACKER_IP_RE|ATTACKER_DOM_RE|PAYLOAD_HASHES)=" ns_quickcheck.rules && echo "WARN: Format-1-Listenvariable neben Format 2 vorhanden"

# --- Format-2-Lint (docs/rules-format-2.md): Shell-Expansion in "...", GNU-Regex-Erweiterungen, Backslash in Klammerausdruecken, IOC-Dubletten
rules_lint() {
  f="$1"; bad=0
  awk -F'\t' -v custom="$(grep -c '^CUSTOM_VERSION=' "$f")" '
    /^: <<'"'"'IOC'"'"'$/ { ioc=1; next } /^IOC$/ { ioc=0; next }
    ioc { if ($0 ~ /^#/ || $0 == "") next; if (NF < 6 || $6 == "") { print "ERROR Format 2: IOC-Zeile ohne 6 Felder oder Fundstelle: " $0; b++ } if (seen[$1 SUBSEP $2]++) { print "ERROR Format 2: IOC-Dublette: " $1 " " $2; b++ }
          if ($1 == "ip" && $2 !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) { print "ERROR Format 2: ip nicht a.b.c.d: " $2; b++ }
          if ($1 == "hash" && $2 !~ /^[0-9a-f]{64}$/) { print "ERROR Format 2: hash nicht 64 Hex: " $2; b++ }
          if ($1 == "path" && ($2 ~ /^\// || $2 ~ /(^|\/)\.\.(\/|$)/)) { print "ERROR Format 2: path muss relativ ohne .. sein: " $2; b++ }
          if ($1 == "dom" && $2 !~ /^[A-Za-z0-9.-]+$/) { print "ERROR Format 2: dom nur [A-Za-z0-9.-]: " $2; b++ }
          if ($1 !~ /^(ip|dom|hash|path)$/) { print "ERROR Format 2: unbekannter typ: " $1; b++ } next }
    /^: <<'"'"'CVE'"'"'$/ { cve=1; next } /^CVE$/ { cve=0; next }
    cve { if ($0 ~ /^#/ || $0 == "") next; n=split($0, c, "::"); if (n < 6 || c[1] !~ /^CTX[0-9]+$/ || c[2] !~ /^CVE-[0-9]{4}-[0-9]+$/ || c[3] !~ /^[0-9]+\.[0-9]+(-FIPS)?$/ || c[4] !~ /^[0-9]+\.[0-9]+$/ || c[5] !~ /^(all|conf:.+|tcpparam:.+)$/) { print "ERROR Format 2: CVE-Zeile ungueltig (CTX::CVE::train::fix::bedingung::text): " $0; b++ }
          if (c[5] ~ /\\[<>bBwWsSdD]|\\[1-9]/ || c[5] ~ /\[[^]]*\\[^]]*\]/) { print "ERROR Format 2: Bedingung mit GNU-Regex-Erweiterung oder Backslash in Klammerausdruck: " c[5]; b++ } next }
    /^RULES_VERSION=/ { have["RULES_VERSION"]=1 } /^TRIGGER_RE=/ { have["TRIGGER_RE"]=1 } /^OBFUSC_RE=/ { have["OBFUSC_RE"]=1 } /^CMD_NAMES=/ { have["CMD_NAMES"]=1 } /^LOGON_HINT_RE=/ { have["LOGON_HINT_RE"]=1 } /^ADMIN_CMD_RE=/ { have["ADMIN_CMD_RE"]=1 } /^CVE_TABLE=/ { have["CVE_TABLE"]=1 }
    /^[A-Z_]+="/ { v=$0; if (v ~ /\$\(|`/ ) { print "ERROR Format 2: Kommandosubstitution in Zuweisung: " substr($0,1,60); b++ } }
    /^[A-Z_]+_RE=/ { v=$0; if (v ~ /\\[<>bBwWsSdD]|\\[1-9]/) { print "ERROR Format 2: GNU-Regex-Erweiterung oder Rueckverweis: " substr($0,1,60); b++ } if (v ~ /\[[^]]*\\[^]]*\]/) { print "ERROR Format 2: Backslash in Klammerausdruck: " substr($0,1,60); b++ } }
    END { split("RULES_VERSION TRIGGER_RE OBFUSC_RE CMD_NAMES LOGON_HINT_RE ADMIN_CMD_RE CVE_TABLE", req, " "); if (!custom) for (i in req) if (!have[req[i]]) { print "ERROR Format 2: Pflichtvariable fehlt: " req[i]; b++ } exit (b ? 1 : 0) }' "$f" || bad=1
  return $bad
}

rules_lint ns_quickcheck.rules || { echo "release.sh: Format-2-Lint FAIL (docs/rules-format-2.md)" >&2; exit 1; }
sh docs/provenance.sh ns_quickcheck.rules
sh ns_quickcheck.sh --testlog docs/testlogs/ | tail -1
sh ns_quickcheck.sh --testlog docs/testlogs/ >/dev/null 2>&1 || { echo "release.sh: --testlog FAIL" >&2; exit 1; }
# Fixtures: voller Offline-Lauf; Verdict und RESULT-Felder gegen docs/testdata/fixture-expected.txt
# Zeile: <fixture>:<ACTION>[:<key>=<wert> <key>=<wert> ...]   (RESULT-Felder, jedes muss exakt stimmen)
while IFS=: read -r fx want fields; do
  [ -n "$fx" ] || continue; case "$fx" in \#*) continue ;; esac
  # Fixture mit Betreiberdatei: Regeldatei und ns_quickcheck.rules.custom der Fixture nebeneinander in ein Arbeitsverzeichnis
  if [ -f "docs/testdata/fixtures/$fx/ns_quickcheck.rules.custom" ] || [ -f "docs/testdata/fixtures/$fx/ns_quickcheck.blocked_ips" ] || [ -f "docs/testdata/fixtures/$fx/ns_quickcheck.trusted_ips" ] || [ -f "docs/testdata/fixtures/$fx/ns_quickcheck.conf" ]; then
    fxd=$(mktemp -d /tmp/qcfx.XXXXXX); cp ns_quickcheck.rules "$fxd/r"; chmod 600 "$fxd/r"
    [ -f "docs/testdata/fixtures/$fx/ns_quickcheck.rules.custom" ] && { cp "docs/testdata/fixtures/$fx/ns_quickcheck.rules.custom" "$fxd/r.custom"; chmod 600 "$fxd/r.custom"; }
    blk=""; [ -f "docs/testdata/fixtures/$fx/ns_quickcheck.blocked_ips" ] && { cp "docs/testdata/fixtures/$fx/ns_quickcheck.blocked_ips" "$fxd/b"; chmod 600 "$fxd/b"; blk="--blocked $fxd/b"; }
    [ -f "docs/testdata/fixtures/$fx/ns_quickcheck.trusted_ips" ] && { cp "docs/testdata/fixtures/$fx/ns_quickcheck.trusted_ips" "$fxd/t"; chmod 600 "$fxd/t"; blk="$blk --trusted $fxd/t"; }
    [ -f "docs/testdata/fixtures/$fx/ns_quickcheck.conf" ] && blk="$blk --conf docs/testdata/fixtures/$fx/ns_quickcheck.conf"
    _fh=100000; [ -f "docs/testdata/fixtures/$fx/refgen.hours" ] && _fh=$(cat "docs/testdata/fixtures/$fx/refgen.hours"); _fn=""; [ -f "docs/testdata/fixtures/$fx/refgen.now" ] && _fn=$(cat "docs/testdata/fixtures/$fx/refgen.now")
    outp=$(QC_NOW="$_fn" sh ns_quickcheck.sh --from "docs/testdata/fixtures/$fx" --rules "$fxd/r" $blk --hours "$_fh" --no-out 2>/dev/null || true); rm -rf "$fxd"
  else
  _fh=100000; [ -f "docs/testdata/fixtures/$fx/refgen.hours" ] && _fh=$(cat "docs/testdata/fixtures/$fx/refgen.hours"); _fn=""; [ -f "docs/testdata/fixtures/$fx/refgen.now" ] && _fn=$(cat "docs/testdata/fixtures/$fx/refgen.now")
  outp=$(QC_NOW="$_fn" sh ns_quickcheck.sh --from "docs/testdata/fixtures/$fx" --hours "$_fh" --no-out 2>/dev/null || true)
  fi
  got=$(printf '%s\n' "$outp" | sed -n 's/^ACTION: \([A-Z_]*\).*/\1/p' | tail -1)
  res=$(printf '%s\n' "$outp" | grep '^RESULT ' | tail -1)
  if [ "$got" != "$want" ]; then echo "FIXTURE $fx: $got, erwartet $want FAIL" >&2; exit 1; fi
  for kv in $fields; do
    case " $res " in *" $kv "*) ;; *) echo "FIXTURE $fx: RESULT ohne '$kv' FAIL ($res)" >&2; exit 1 ;; esac
  done
  echo "FIXTURE $fx: $got PASS${fields:+ ($fields)}"
done < docs/testdata/fixture-expected.txt
