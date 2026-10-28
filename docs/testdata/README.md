# Testdaten

`ns_quickcheck.rules.2026-10-06` ist der rekonstruierte Stand der Regeldatei vor Einarbeitung von CTX697174. Eingabe für den Abnahmetest des KI-Prompts (`appliance/ns_quickcheck_rules_prompt.md`, Abschnitt "Abnahmetest"): zusammen mit dem Text von CTX697174 muss die KI die SAML-Zeilen der CVE-Tabelle und Slot B der FIX_*-Werte erzeugen. Nicht auf Appliances einsetzen.

Die Präfix-Prüfung (`docs/rules-prefix-check.sh`) läuft gegen den Stand `2026-10-06` und die aktuelle Regeldatei.

`fixtures/clean` und `fixtures/compromised` sind Verzeichnisse im Appliance-Layout für den vollen Offline-Lauf (`--from`, `--hours 100000`); erwartete Verdicts in `fixture-expected.txt`. Beide enthalten Angriffszeilen bzw. einen Payload-Pfad: nie auf eine Appliance kopieren.

Nur dieser eine Stand liegt hier; die Regelhistorie steht in `ns_quickcheck.rules.changelog.md` und ab v17.29 in den Git-Tags `rules-<datum>`. Kommentare in diesem Stand nennen Drittquellen nur als "Community" oder "Drittquelle"; Indikatoren aus Blöcken Dritter mit eingeschränkter Erlaubnis enthält er nicht (bereinigt am 2026-10-19).
