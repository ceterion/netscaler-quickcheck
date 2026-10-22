#!/bin/sh
# provenance.sh - erzeugt aus der Regeldatei das Herkunftsprotokoll: je Indikator Quelle, Veroeffentlichungsdatum,
# Fundstelle, Status und Regelstand der Aufnahme; dazu die CVE-Tabelle mit Bulletin-URL. Wird von release.sh aufgerufen.
# Aufruf: sh docs/provenance.sh [ns_quickcheck.rules]   Ausgabe: ns_quickcheck.rules.provenance.csv und .md
# Changelog: 1.0 2026-10-19 Erstfassung
R="${1:-ns_quickcheck.rules}"; CSV="${R}.provenance.csv"; MD="${R}.provenance.md"
RV=$(grep -m1 '^RULES_VERSION=' "$R" | sed 's/^RULES_VERSION="\(.*\)"$/\1/')
printf 'typ;wert;quelle;veroeffentlicht;fundstelle;status;regelstand\n' > "$CSV"
awk -F'\t' "/^: <<'IOC'\$/ { f=1; next } /^IOC\$/ { f=0 } f && !/^#/ && NF>=6 {
  st=\"belegt\"; if (\$6 ~ /ENTFERNEN/) st=\"ENTFERNEN\"; else if (\$6 ~ /PRUEFEN/) st=\"PRUEFEN\";
  printf \"%s;%s;%s;%s;%s;%s;%s\\n\", \$1, \$2, \$3, \$4, \$6, st, (NF>=7 ? \$7 : \"\") }" "$R" >> "$CSV"
awk -F'::' '/^CTX[0-9]+::CVE-/ { printf "cve;%s %s Fix %s;Citrix;;https://support.citrix.com/external/article/%s/;belegt;\n", $2, $3, $4, $1 }' "$R" >> "$CSV"
{ printf '# Herkunftsprotokoll ns_quickcheck.rules %s\n\nErzeugt aus der Regeldatei durch docs/provenance.sh (Beschreibung: ns_quickcheck_README.md, Abschnitt 8.2); je Wert Quelle, Veroeffentlichungsdatum beim Erstautor, Fundstelle, Status und Regelstand der Aufnahme. Status PRUEFEN = Fundstelle noch nicht verifiziert, Wert inaktiv; ENTFERNEN = keine Primaerquelle, wird beim naechsten Regelstand geloescht.\n\n' "$RV"
  printf '| Typ | Wert | Quelle | Veroeffentlicht | Fundstelle | Status | Regelstand |\n|---|---|---|---|---|---|---|\n'
  tail -n +2 "$CSV" | awk -F';' '{ printf "| %s | %s | %s | %s | %s | %s | %s |\n", $1, $2, $3, $4, $5, $6, $7 }'; } > "$MD"
n=$(tail -n +2 "$CSV" | wc -l | tr -d ' '); b=$(grep -c ';belegt;' "$CSV"); echo "provenance: $n Zeilen, $b belegt, $(grep -c ';PRUEFEN;' "$CSV") PRUEFEN, $(grep -c ';ENTFERNEN;' "$CSV") ENTFERNEN -> $CSV, $MD"
