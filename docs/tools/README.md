# docs/tools

Werkzeuge der Entwicklung, nicht fuer die Appliance.

| Datei | Zweck |
|---|---|
| `refnorm.sh` | Normalisierung eines Reports (Laufzeit, Zeitstempel, Hashes, Pfade) fuer Referenzvergleiche; von `release.sh` und `refgen.sh` eingebunden |
| `refgen.sh` | erzeugt die Referenzreports unter `docs/testdata/reference/<fixture>.<sprache>.txt` aus dem aktuellen Script; nur nach gewollter Textaenderung ausfuehren, `release.sh` vergleicht jeden Lauf dagegen |
| `refcompare.sh` | vergleicht zwei Script-Staende ueber alle Fixtures byteweise (alle Ausgabedateien); diente der Abnahme des Katalog-Umbaus 18.0 |
| `msgmap_17.44.tsv`, `msg_notizen_17.44.md`, `msg_rewrite_17.44.py` | Zuordnungstabelle, Notizen und Umbauwerkzeug des Katalog-Umbaus (Script 17.44 nach 18.0); Nachschlagewerk, nicht erneut auszufuehren |
