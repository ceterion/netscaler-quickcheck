#!/bin/sh
# refcompare.sh <referenz-script> <neues-script> [--lang xx]: laeuft beide Scripts ueber alle Fixtures (Report, JSON, anon, Listen)
# und vergleicht die normalisierten Ausgaben byteweise. Normalisiert werden nur Laufzeit, Zeitstempel des Laufs und der Arbeitsordner.
REF=$(cd "$(dirname "$1")" && pwd)/$(basename "$1"); NEW=$(cd "$(dirname "$2")" && pwd)/$(basename "$2"); shift 2; LANGOPT="$*"
REPO=$(cd "$(dirname "$0")/../.." && pwd); FX="$REPO/docs/testdata/fixtures"; T=$(mktemp -d); fail=0
norm() { sed -E 's/[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} (UTC|CET|CEST)/TS/; s/runtime=[0-9]+s/runtime=Ns/; s/_[0-9]{8}_[0-9]{6}/_TS/g; s#'"$T"'[^ ]*#WORK#g; s/"ts": "[^"]*"/"ts": "TS"/; s/script_sha256=[0-9a-f]+/script_sha256=X/; s/"script_sha256": "[0-9a-f]+"/"script_sha256": "X"/; s/^(# .*)seit [0-9-]+ [0-9:]+/\1seit TS/; s/^(# .*)since [0-9-]+ [0-9:]+/\1since TS/; s/"version": "[0-9.]+"/"version": "V"/; s/ns_quickcheck [0-9]+\.[0-9]+ /ns_quickcheck V /; s/netscaler-quickcheck [0-9]+\.[0-9]+ /netscaler-quickcheck V /; s/msg_sha256=[0-9a-f]+/msg_sha256=X/; s/ msg_sha256=X//; s/ lang=de//; s/"lang": "de", //; s/"msg_sha256": "[0-9a-f]+", //; s/"code": "[A-Z0-9_]*", //g; s/"runtime": "[0-9]+s"/"runtime": "Ns"/; s/ns_quickcheck share [0-9.]+ /ns_quickcheck share V /; s#'"$(dirname "$REF")"'#SELFDIR#g; s#'"$(dirname "$NEW")"'#SELFDIR#g' "$1"; }
for d in "$FX"/*/; do fx=$(basename "$d")
  for which in ref new; do
    if [ "$which" = ref ]; then S="$REF"; else S="$NEW"; fi
    O="$T/$which/$fx"; mkdir -p "$O"; cp "$REPO/ns_quickcheck.rules" "$O/r"; chmod 600 "$O/r"
    extra=""; [ -f "$d/blocked_ips" ] && extra="$extra --blocked $d/blocked_ips"; [ -f "$d/trusted_ips" ] && extra="$extra --trusted $d/trusted_ips"; [ -f "$d/ns_quickcheck.trusted_ips" ] && extra="$extra --trusted $d/ns_quickcheck.trusted_ips"; [ -f "$d/ns_quickcheck.blocked_ips" ] && extra="$extra --blocked $d/ns_quickcheck.blocked_ips"; [ -f "$d/ns_quickcheck.conf" ] && extra="$extra --conf $d/ns_quickcheck.conf"; [ -f "$d/whitelist" ] && extra="$extra --whitelist $d/whitelist"
    ( cd "$O" && sh "$S" --from "$d" --rules "$O/r" --hours 1000000 --out "$O/report.txt" $extra $( [ "$which" = new ] && echo "$LANGOPT" ) > "$O/terminal.txt" 2> "$O/stderr.txt" )
    rm -f "$O/r" "$O"/*.map
    for f in "$O"/*_20[0-9][0-9][0-9][0-9][0-9][0-9]_[0-9][0-9][0-9][0-9][0-9][0-9]*; do [ -e "$f" ] && mv "$f" "$(echo "$f" | sed -E 's/_[0-9]{8}_[0-9]{6}/_TS/')"; done
  done
  for f in $(cd "$T/ref/$fx" && ls); do
    if [ ! -f "$T/new/$fx/$f" ]; then echo "FEHLT $fx/$f"; fail=1; continue; fi
    if ! diff -q <(norm "$T/ref/$fx/$f") <(norm "$T/new/$fx/$f") >/dev/null 2>&1; then echo "DIFF $fx/$f"; diff <(norm "$T/ref/$fx/$f") <(norm "$T/new/$fx/$f") | head -12 | cut -c1-200; fail=1; fi
  done
done
[ "$fail" -eq 0 ] && echo "refcompare: alle Fixtures byteidentisch" || echo "refcompare: Abweichungen"
rm -rf "$T"; exit $fail
