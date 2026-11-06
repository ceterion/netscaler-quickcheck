#!/bin/sh
# refgen.sh [--lang xx] [fixture ...]: erzeugt normalisierte Referenzreports unter docs/testdata/reference/<fixture>.<lang>.txt aus dem aktuellen Script.
# Nur bewusst ausfuehren, wenn eine Ausgabeaenderung gewollt ist; release.sh vergleicht jeden Lauf gegen diese Dateien.
REPO=$(cd "$(dirname "$0")/../.." && pwd); FX="$REPO/docs/testdata/fixtures"; LANG_=de; [ "$1" = "--lang" ] && { LANG_="$2"; shift 2; }
T=$(mktemp -d); mkdir -p "$REPO/docs/testdata/reference"
. "$REPO/docs/tools/refnorm.sh"
for d in "$FX"/*/; do fx=$(basename "$d"); [ $# -gt 0 ] && ! echo " $* " | grep -q " $fx " && continue
  O="$T/$fx"; mkdir -p "$O"; cp "$REPO/ns_quickcheck.rules" "$O/r"; chmod 600 "$O/r"
  extra=""; [ -f "$d/blocked_ips" ] && extra="$extra --blocked $d/blocked_ips"; [ -f "$d/trusted_ips" ] && extra="$extra --trusted $d/trusted_ips"; [ -f "$d/ns_quickcheck.trusted_ips" ] && extra="$extra --trusted $d/ns_quickcheck.trusted_ips"; [ -f "$d/ns_quickcheck.blocked_ips" ] && extra="$extra --blocked $d/ns_quickcheck.blocked_ips"; [ -f "$d/ns_quickcheck.conf" ] && extra="$extra --conf $d/ns_quickcheck.conf"; [ -f "$d/whitelist" ] && extra="$extra --whitelist $d/whitelist"
  _hours=1000000; [ -f "$d/refgen.hours" ] && _hours=$(cat "$d/refgen.hours"); _now=""; [ -f "$d/refgen.now" ] && _now=$(cat "$d/refgen.now")
  ( cd "$O" && QC_NOW="$_now" sh "$REPO/ns_quickcheck.sh" --from "$d" --rules "$O/r" --hours "$_hours" --out "$O/report.txt" --lang "$LANG_" $extra > /dev/null 2>&1 )
  refnorm "$O/report.txt" "$T" > "$REPO/docs/testdata/reference/$fx.$LANG_.txt"; echo "$fx.$LANG_.txt"
done
rm -rf "$T"
