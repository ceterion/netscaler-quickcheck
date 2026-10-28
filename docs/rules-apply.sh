#!/bin/sh
# rules-apply.sh 2.5 - wendet einen Regel-Patch additiv auf die Regeldatei an und prueft das Ergebnis.
# 2.5 (2026-10-28): Fix-Build "pending" in CVE_TABLE-Zeilen zugelassen.
# 2.4 (2026-10-22): Pfade absolut, Testlog-Schritt schlug mit relativem Ziel aus dem Repo-Stamm fehl.
# Aufruf: sh docs/rules-apply.sh <ziel> <patch>   (Ziel wird gesichert und aktualisiert; Ziel ist ns_quickcheck.rules oder ns_quickcheck.rules.custom)
#         sh docs/rules-apply.sh <alte Regeldatei> <neue Regeldatei> <Patch>   (Ergebnis in neue Datei, Ziel bleibt unveraendert)
# Patch-Format (eine Anweisung je Zeile, von ns_quickcheck_rules_prompt.md erzeugt):
#   # rules-patch 1  <CTX>  <Datum>        Kopfzeile, Pflicht
#   RULES_VERSION: <Datum oder Datum+Buchstabe>
#   RULES_SOURCE: <Quelle>                 wird angehaengt
#   HERKUNFT: +<Datum> <Quelle>: <Satz>    Kommentar, wird ueber die erste geaenderte Variable gesetzt
#   CVE_TABLE: <Zeile im Tabellenformat>   wird vor dem schliessenden ' eingefuegt
#   FIX_14_1: <Build>                      ersetzt den zweiten Slot (Slot 1 bleibt), ebenso FIX_13_1, FIX_13_1_FIPS, FIX_14_1_FIPS
#   <NAME>_RE: <Regex-Teil>                wird mit | angehaengt (nur Variablen, die in der alten Datei existieren)
#   PAYLOAD_PATHS: <Pfad>                  wird mit Leerzeichen angehaengt
#   STOCK_FILE_HASHES: <pfad>::<sha256>::<build>   wird mit Leerzeichen angehaengt
#   EOL_RELEASES: <Release>                wird mit Leerzeichen angehaengt
# Der Patch kann nur anhaengen, nie loeschen oder ersetzen; unbekannte Variablen werden abgelehnt.
# Copyright 2026 ceterion AG. SPDX-License-Identifier: Apache-2.0. Provided "AS IS".
set -e
# Zwei Formen: <ziel> <patch> (Ziel wird gesichert und an Ort und Stelle aktualisiert) oder <alt> <neu> <patch> (Ergebnis in neue Datei)
INPLACE=0
if [ $# -eq 2 ]; then INPLACE=1; OLD="$1"; PATCH="$2"; NEW="$1.apply.$$"
elif [ $# -eq 3 ]; then OLD="$1"; NEW="$2"; PATCH="$3"
else echo "usage: $0 <ziel> <patch>   oder   $0 <alt> <neu> <patch>" >&2; exit 3; fi
HERE=$(dirname "$0")
[ -f "$OLD" ]   || { echo "ERROR: alte Regeldatei fehlt: $OLD" >&2; exit 3; }
[ -f "$PATCH" ] || { echo "ERROR: Patch fehlt: $PATCH" >&2; exit 3; }
[ -e "$NEW" ] && { echo "ERROR: $NEW existiert bereits, nicht ueberschreiben" >&2; exit 3; }
head -1 "$PATCH" | grep -qE '^# rules-patch 1 ' || { echo "ERROR: Patch-Kopfzeile fehlt (# rules-patch 1  <CTX>  <Datum>)" >&2; exit 3; }

# ---- Patch pruefen, bevor etwas geschrieben wird
ERR=0; HERK=""; FIRSTVAR=""
grep -vE '^#|^[[:space:]]*$' "$PATCH" | tr -d '\r' | while IFS= read -r line; do
  key=${line%%:*}; val=${line#*:}; val=$(echo "$val" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
  [ -n "$val" ] || { echo "ERROR: leerer Wert: $line" >&2; exit 4; }
  case "$key" in
    RULES_VERSION|RULES_SOURCE|HERKUNFT|CVE_TABLE|PAYLOAD_PATHS|PAYLOAD_HASHES|STOCK_FILE_HASHES|EOL_RELEASES|IOC) ;;
    FIX_14_1|FIX_13_1|FIX_13_1_FIPS|FIX_14_1_FIPS) echo "$val" | grep -qE '^[0-9]+\.[0-9]+$' || { echo "ERROR: Fix-Build nicht im Format NN.NN: $line" >&2; exit 4; } ;;
    *_RE) grep -qE "^$key=" "$OLD" || { echo "ERROR: Variable nicht in der Regeldatei, nicht anhaengbar: $key" >&2; exit 4; } ;;
    *) echo "ERROR: unbekannte Anweisung: $key" >&2; exit 4 ;;
  esac
  case "$key" in CVE_TABLE) echo "$val" | grep -qE '^CTX[0-9]+::CVE-[0-9]{4}-[0-9]+::[0-9.]+(-FIPS)?::([0-9]+\.[0-9]+|pending)::' || { echo "ERROR: CVE_TABLE-Zeile nicht im Format CTX::CVE::Train::Fix::Bedingung::Text: $line" >&2; exit 4; } ;; esac
done

# ---- anwenden
cp "$OLD" "$NEW"
apply_line() { # $1 key $2 val
  key="$1"; val="$2"
  case "$key" in
    RULES_VERSION)
      if grep -q '^CUSTOM_VERSION=' "$NEW"; then
        awk -v v="$val" '/^CUSTOM_VERSION=/ {print "CUSTOM_VERSION=\"" v "\""; next} {print}' "$NEW" > "$NEW.tmp" && mv "$NEW.tmp" "$NEW"
      else
        awk -v v="$val" '/^RULES_VERSION=/ {print "RULES_VERSION=\"" v "\""; next} {print}' "$NEW" > "$NEW.tmp" && mv "$NEW.tmp" "$NEW"
      fi ;;
    RULES_SOURCE)
      awk -v v="$val" '/^RULES_SOURCE="/ { n=length($0); for(i=n;i>0;i--) if(substr($0,i,1)=="\"") break; print substr($0,1,i-1) ", " v substr($0,i); next } {print}' "$NEW" > "$NEW.tmp" && mv "$NEW.tmp" "$NEW" ;;
    HERKUNFT)
      HERK="$val" ;;
    CVE_TABLE)
      if grep -q '^CUSTOM_VERSION=' "$NEW"; then
        # Custom-Datei: in den CVE-Block (anlegen, falls er fehlt); Hinweis, wenn die Regeldatei daneben dieselbe CVE anders bewertet
        grep -q "^: <<'CVE'$" "$NEW" || printf "%s\n" ": <<'CVE'" "CVE" >> "$NEW"
        k5=$(echo "$val" | cut -d: -f1-9); k3=$(echo "$val" | awk -F'::' '{print $1 "::" $2 "::" $3}')
        if awk -v k="$k5" '/^: <<'"'"'CVE'"'"'$/ { f=1; next } /^CVE$/ { f=0 } f && index($0, k)==1 { hit=1 } END { exit (hit ? 0 : 1) }' "$NEW"; then
          echo "WARN: CVE-Zeile schon vorhanden, nicht doppelt angehaengt: $k3"; return 0; fi
        RF="$(dirname "$OLD")/ns_quickcheck.rules"
        if [ -f "$RF" ]; then
          rfix=$(awk -F'::' -v k="$k3" '($1 "::" $2 "::" $3) == k { print $4 " (" $5 ")" }' "$RF" | sort -u | tr '\n' ' ' | sed 's/ $//')
          cfix=$(echo "$val" | awk -F'::' '{print $4}')
          if [ -n "$rfix" ]; then echo "HINWEIS: Regeldatei bewertet $k3 mit Fix $rfix, Custom mit $cfix; beide werden geprueft, das strengere Ergebnis zaehlt"; fi
        fi
        awk -v v="$val" '/^CVE$/ && !done { print v; done=1 } { print }' "$NEW" > "$NEW.tmp" && mv "$NEW.tmp" "$NEW"
      else
        # vor das alleinstehende schliessende ' des CVE_TABLE-Blocks
        awk -v v="$val" 'BEGIN{inb=0} /^CVE_TABLE=\x27/{inb=1} inb==1 && /^\x27$/{print v; inb=0} {print}' "$NEW" > "$NEW.tmp" && mv "$NEW.tmp" "$NEW"
      fi ;;
    FIX_14_1|FIX_13_1|FIX_13_1_FIPS|FIX_14_1_FIPS)
      awk -v k="$key" -v v="$val" '$0 ~ "^"k"=" { match($0,/"[^"]*"/); inner=substr($0,RSTART+1,RLENGTH-2); split(inner,a," "); rest=substr($0,RSTART+RLENGTH); print k"=\""a[1]" "v"\""rest; next } {print}' "$NEW" > "$NEW.tmp" && mv "$NEW.tmp" "$NEW" ;;
    IOC)
      # Format 2: Zeile "typ<TAB>wert<TAB>quelle<TAB>datum<TAB>klasse<TAB>fundstelle" vor der schliessenden Marke IOC einfuegen
      printf '%s\n' "$val" | awk -F'\t' 'NF<6 || $6=="" { print "ERROR: IOC-Zeile braucht 6 Felder mit Fundstelle: " $0 > "/dev/stderr"; exit 7 }' || exit 7
      rv=$(grep -m1 -E '^(RULES|CUSTOM)_VERSION=' "$NEW" | sed 's/^[A-Z]*_VERSION="\(.*\)"$/\1/')
      w=$(printf '%s' "$val" | cut -f2)
      if awk -F'\t' -v w="$w" 'f && !/^#/ && NF>=6 && $2==w { hit=1 } /^: <<'"'"'IOC'"'"'$/ { f=1 } /^IOC$/ { f=0 } END { exit (hit ? 0 : 1) }' "$NEW"; then
        echo "WARN: Wert schon vorhanden, Zeile wird nicht doppelt angehaengt: $w"; return 0; fi
      awk -v line="$val	$rv" '/^IOC$/ && !done { print line; done=1 } { print }' "$NEW" > "$NEW.tmp" && mv "$NEW.tmp" "$NEW" ;;
    PAYLOAD_PATHS|PAYLOAD_HASHES|STOCK_FILE_HASHES|EOL_RELEASES)
      awk -v k="$key" -v v="$val" '$0 ~ "^"k"=" { q=substr($0,length(k)+2,1); n=length($0); for(i=n;i>length(k)+2;i--) if(substr($0,i,1)==q) break; head=substr($0,1,i-1); tail=substr($0,i); if (head ~ "=" q "$") print head v tail; else print head" "v tail; next } {print}' "$NEW" > "$NEW.tmp" && mv "$NEW.tmp" "$NEW" ;;
    *_RE)
      awk -v k="$key" -v v="$val" '$0 ~ "^"k"=" { q=substr($0,length(k)+2,1); n=length($0); for(i=n;i>length(k)+2;i--) if(substr($0,i,1)==q) break; head=substr($0,1,i-1); tail=substr($0,i); if (head ~ "=" q "$") print head v tail; else print head"|"v tail; next } {print}' "$NEW" > "$NEW.tmp" && mv "$NEW.tmp" "$NEW" ;;
  esac
  [ -n "$FIRSTVAR" ] || case "$key" in RULES_VERSION|RULES_SOURCE|HERKUNFT) ;; *) FIRSTVAR="$key" ;; esac
}
grep -vE '^#|^[[:space:]]*$' "$PATCH" | tr -d '\r' > "$NEW.patchlines"
while IFS= read -r line; do
  key=${line%%:*}; val=${line#*:}; val=$(echo "$val" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
  apply_line "$key" "$val"
done < "$NEW.patchlines"
rm -f "$NEW.patchlines"
# Herkunftszeile ueber die erste geaenderte Variable (CVE_TABLE: ueber den Block)
if [ -n "$HERK" ] && [ -n "$FIRSTVAR" ]; then
  awk -v k="$FIRSTVAR" -v h="# $HERK" 'done==0 && $0 ~ "^"k"=" {print h; done=1} {print}' "$NEW" > "$NEW.tmp" && mv "$NEW.tmp" "$NEW"
fi
# absolute Pfade: ns_quickcheck.sh wechselt das Verzeichnis, relative Regelpfade gingen im Testlog-Schritt verloren (2.4)
abspath() { case "$1" in /*) printf '%s\n' "$1" ;; *) printf '%s/%s\n' "$(pwd)" "$1" ;; esac; }
OLD=$(abspath "$OLD"); NEW=$(abspath "$NEW"); PATCH=$(abspath "$PATCH")

# ---- pruefen

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

echo "== Format-2-Lint"; rules_lint "$NEW" && echo "ok" || { echo "ERROR: Format-2-Lint fehlgeschlagen, siehe docs/rules-format-2.md" >&2; exit 5; }
echo "== Syntax"; if sh -n "$NEW"; then echo "ok"; else echo "ERROR: Syntaxfehler in $NEW, Datei nicht verwenden" >&2; exit 5; fi
echo "== Praefix-Pruefung"; sh "$HERE/rules-prefix-check.sh" "$OLD" "$NEW" || exit 5
if grep -q '^CUSTOM_VERSION=' "$NEW"; then echo "== Testlogs: entfaellt fuer Custom-Datei (nur IOC-Abschnitt); Lauf auf der Appliance mit beiden Dateien"; elif [ -f "$HERE/../ns_quickcheck.sh" ] && [ -d "$HERE/testlogs" ]; then
  echo "== Testlogs"; sh "$HERE/../ns_quickcheck.sh" --testlog "$HERE/testlogs/" --rules "$NEW" | tail -1
  sh "$HERE/../ns_quickcheck.sh" --testlog "$HERE/testlogs/" --rules "$NEW" >/dev/null 2>&1 || { echo "ERROR: --testlog FAIL, Details: sh ./ns_quickcheck.sh --testlog ./docs/testlogs/ --rules $NEW" >&2; exit 5; }
fi
echo "== Ergebnis"
if [ "$INPLACE" -eq 1 ]; then
  oldv=$(grep -m1 -E '^(RULES|CUSTOM)_VERSION=' "$OLD" | sed 's/^[A-Z]*_VERSION="\(.*\)"$/\1/'); BAK="$OLD.bak_${oldv:-ohne}"; i=1
  while [ -e "$BAK" ]; do i=$((i+1)); BAK="$OLD.bak_${oldv:-ohne}.$i"; done
  cp -p "$OLD" "$BAK" && mv "$NEW" "$OLD" && NEW="$OLD" && echo "$(basename "$OLD") aktualisiert, Sicherung: $BAK"
fi
grep -E '^(RULES|CUSTOM)_VERSION=' "$NEW"
if command -v sha256sum >/dev/null 2>&1; then sha256sum "$NEW"; elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$NEW"; else sha256 "$NEW"; fi
echo "Naechster Schritt: Changelog-Eintrag mit diesem Hash unter Nachher, dann WORKFLOW.de.md Schritt 5 (Lauf auf einer Appliance)."
