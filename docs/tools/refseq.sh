#!/bin/sh
# refseq.sh gen|check: zwei Laeufe hintereinander im selben Reportverzeichnis (compromised, dann clean) mit --out; prueft, was
# Einzel-Fixtures nicht sehen: Vergleich mit dem letzten Lauf (new/gone), Kontendateien, kumulierte Listen, JSON mit code,
# anon-Fassungen. Referenzen unter docs/testdata/reference/seq/.
REPO=$(cd "$(dirname "$0")/../.." && pwd); FX="$REPO/docs/testdata/fixtures"; REF="$REPO/docs/testdata/reference/seq"; MODE="${1:-check}"
. "$REPO/docs/tools/refnorm.sh"
T=$(mktemp -d); O="$T/out"; mkdir -p "$O"; cp "$REPO/ns_quickcheck.rules" "$T/r"; chmod 600 "$T/r"
norm_json() { sed -E 's/"ts": "[^"]*"/"ts": "TS"/; s/"runtime": "[0-9]+s"/"runtime": "Ns"/; s/"script_sha256": "[0-9a-f]+"/"script_sha256": "X"/; s/"msg_sha256": "[0-9a-f]+"/"msg_sha256": "X"/; s/"version": "[0-9.]+"/"version": "V"/; s/_[0-9]{8}_[0-9]{6}/_TS/g; s#'"$T"'[^"]*#WORK#g; s#/home/[^" ]*/netscaler-quickcheck/#REPO/#g; s/"profile": \[[^]]*\]/"profile": []/; s/[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}/T/g' "$1"; }
norm_tsv() { sed -E 's/[0-9]{8}_[0-9]{6}/TS/g; s/[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}/T/g; s/[0-9]{4}-[0-9]{2}-[0-9]{2}/D/g; s/ns_quickcheck [0-9.]+,/ns_quickcheck V,/; s#'"$T"'[^ 	]*#WORK#g; s#/home/[^ 	]*/netscaler-quickcheck/#REPO/#g' "$1"; }
run() { ( cd "$O" && sh "$REPO/ns_quickcheck.sh" --from "$FX/$1" --rules "$T/r" --hours 1000000 --out "$O/ns_quickcheck_gw-01_$2_120000.txt" --lang de > /dev/null 2>&1 ); }
run shared-hit 20261101; sleep 1; run clean 20261102
mkdir -p "$REF"; rc=0
cmp_or_gen() { # name, normalized-content-file
  if [ "$MODE" = gen ]; then cp "$2" "$REF/$1"; echo "seq/$1"
  else if ! diff -q "$REF/$1" "$2" >/dev/null 2>&1; then echo "release.sh: FAIL: Sequenz-Referenz $1 weicht ab:" >&2; diff "$REF/$1" "$2" | head -6 >&2; rc=1; fi; fi; }
refnorm "$O/ns_quickcheck_gw-01_20261102_120000.txt" "$T" > "$T/n1"; cmp_or_gen clean-after-compromised.de.txt "$T/n1"
norm_json "$O/ns_quickcheck_gw-01_20261102_120000.json" > "$T/n2"; cmp_or_gen clean-after-compromised.de.json "$T/n2"
norm_json "$O/ns_quickcheck_gw-01_20261101_120000.json" > "$T/n3"; cmp_or_gen shared-hit.de.json "$T/n3"
norm_tsv "$O/ns_quickcheck_gw-01_20261101_120000_accounts.tsv" > "$T/n4"; cmp_or_gen shared-hit_accounts.tsv "$T/n4"
norm_tsv "$O/ns_quickcheck_observed_accounts.tsv" > "$T/n5"; cmp_or_gen observed_accounts.tsv "$T/n5"
norm_tsv "$O/ns_quickcheck_observed_ips.tsv" > "$T/n6"; cmp_or_gen observed_ips.tsv "$T/n6"
_an=$(ls "$O"/ns_quickcheck_gw-01_*_anon.txt | tail -1); refnorm "$_an" "$T" > "$T/n7"; cmp_or_gen clean-after-compromised_anon.de.txt "$T/n7"
grep -c '"code": "[A-Z0-9_]\+"' "$O/ns_quickcheck_gw-01_20261101_120000.json" | grep -q '^[1-9]' || { echo "release.sh: FAIL: Sequenz: JSON ohne code" >&2; rc=1; }
grep -q 'new=0 gone=[1-9]' "$O/ns_quickcheck_gw-01_20261102_120000.txt" || { echo "release.sh: FAIL: Sequenz: Vergleich mit letztem Lauf zeigt kein gone" >&2; rc=1; }
rm -rf "$T"; [ "$MODE" = gen ] || { [ $rc -eq 0 ] && echo "SEQUENZ: 7 Referenzen identisch"; }; exit $rc
