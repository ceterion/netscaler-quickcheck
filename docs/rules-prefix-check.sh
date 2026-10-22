#!/bin/sh
# rules-prefix-check.sh <alte Regeldatei> <neue Regeldatei>
# Praefix-Pruefung: jeder bisherige Wert (ausser FIX_*, RULES_* und Kommentare) muss im neuen Wert enthalten sein,
# d. h. die neue Zeile beginnt mit der alten Zeile ohne schliessendes Anfuehrungszeichen. Ausgabe nur bei Verstoss.
# Copyright 2026 ceterion AG. SPDX-License-Identifier: Apache-2.0. Provided "AS IS".
[ $# -eq 2 ] || { echo "usage: $0 <alt> <neu>" >&2; exit 3; }
rc=0
TMPW="${TMPDIR:-/tmp}/prefix.$$"
grep -vE '^(FIX_|RULES_|CUSTOM_|#)|^[[:space:]]*$' "$1" | sed "s/['\"]\$//" | while IFS= read -r old; do
  [ -n "$old" ] || continue
  if ! grep -qF -- "$old" "$2"; then echo "WARN: bisheriger Wert nicht mehr enthalten: $(echo "$old" | cut -c1-80)"; echo "  Hilfe: WORKFLOW.de.md, Schritt 4.2"; rc=1; fi
done > "$TMPW"
if [ -s "$TMPW" ]; then cat "$TMPW"; rm -f "$TMPW"; exit 1; fi
rm -f "$TMPW"; echo "Praefix-Pruefung ok"; exit 0
