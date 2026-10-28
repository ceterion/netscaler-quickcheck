# Ablauf: Neue Indikatoren und neue Bulletins

English: [WORKFLOW.md](WORKFLOW.md)

Für Admins, die den Quickcheck betreiben, ohne das Repo zu pflegen. Zielzeit 20 Minuten.

## Zwei Dateien, zwei Verantwortungen

| Datei | Pflegt | Enthält | Beim Update |
|---|---|---|---|
| `ns_quickcheck.rules` | ceterion | Prüfmuster, Fix-Builds je CVE (`CVE_TABLE`), belegte Indikatoren mit Fundstelle | wird ersetzt |
| `ns_quickcheck.rules.custom` | der Betreiber | eigene Indikatoren (IOC-Block) und eigene Fix-Build-Zeilen (CVE-Block): Feldbefunde, Werte und Bulletins, die ceterion noch nicht nachgezogen hat | bleibt |

Beide Dateien werden zusammen geprüft. Steht eine CVE in beiden, aber mit anderem Fix-Build, prüft das Script beide Zeilen und zeigt beide Ergebnisse; das strengere zählt. Eine Custom-Zeile kann ein Gerät deshalb nie grüner machen als die Regeldatei, nur strenger. Was der Betreiber nicht über die Custom-Datei einbringen kann: neue Prüfmuster (Regex) und Änderungen am Script; dafür Schritt 7.

**Voraussetzungen, einmalig**
- Das Repo am Arbeitsplatz entpackt oder geklont, Terminal mit `sh`, `grep`, `awk`, `perl` (macOS, Linux, Windows mit WSL). Der Ordner mit `ns_quickcheck.rules`, `docs/` und deiner Custom-Datei ist unten der "Werkzeugordner".
- Zugriff auf eine Appliance als `nsroot` per SSH und SCP, zuerst ein Lab oder ein HA-Partner.
- Ein KI-Konto (ChatGPT, Claude, Mistral oder ein firmeneigener Dienst). In diesem Ablauf werden keine Betreiberdaten übertragen, deshalb reicht jedes.
- Beim ersten Mal: `ns_quickcheck.rules.custom.example` kopieren und als `ns_quickcheck.rules.custom` benennen; sie ist leer bis auf den Kopf.

## Kurzfassung

| # | Schritt | Befehl oder Eingabe |
|---|---|---|
| 0 | Nur bei Routine ohne Anlass: Recherche-Prompt, Liste neuer Bulletins und Berichte | `ns_quickcheck_research_prompt.md` |
| 1 | Regel-Prompt mit Bericht oder Bulletin, Regeldatei und Custom-Datei | `ns_quickcheck_rules_prompt.md`, Block 0 und 1 |
| 2 | Ausgabe prüfen: Zitat zu jeder Zahl, URL des Erstautors zu jedem Indikator | im Chat |
| 3 | Den `# rules-patch`-Block aus dem Chat als `ns_quickcheck.rules.patch` im Werkzeugordner speichern, dann anwenden; die alte Custom-Datei wird automatisch gesichert | `sh docs/rules-apply.sh ns_quickcheck.rules.custom ns_quickcheck.rules.patch` |
| 4 | Prüfungen lesen: Lint, Syntax, Hinweise; Meldung "aktualisiert, Sicherung: ..." | Ausgabe von Schritt 3 |
| 5 | Lauf auf einer Appliance: Custom-Datei neben die Regeldatei; Kopfzeile "Custom-Datei des Betreibers geladen" | `sh ns_quickcheck.sh --no-out` |
| 6 | Custom-Datei auf alle Appliances, Lauf, `CUSTOM_VERSION` je Gerät notieren; `ns_quickcheck.rules` nicht anfassen | `chmod 600`, root:wheel |
| 7 | Freiwillig: belegte Zeilen als Issue, damit sie in die Regeldatei kommen | GitHub |

## Einstieg

**Bericht oder Bulletin bekannt** (Citrix-Security-Mail, CISA, Hersteller-Blog, Kollege): weiter bei Schritt 1.

**Routine ohne Anlass** (empfohlen alle zwei Tage, nach einem Bulletin täglich für eine Woche):
1. `ns_quickcheck_research_prompt.md` öffnen, den Prompt-Block kopieren, in ein KI-Konto einfügen.
2. Parameter eintragen: Stichtag (Datum der letzten Anfrage, beim ersten Mal das Datum aus `RULES_VERSION`), Regelstand, Script-Version.
3. Ergebnis lesen: "Änderungen seit" nennt neue Bulletins und Berichte. Keine: fertig, Datum notieren. Eines oder mehrere: je Bulletin oder Bericht ab Schritt 1.

Häufigster Fehler: Der Chat nennt eine Quelle ohne URL oder ein Bulletin ohne CTX-Nummer. Jede URL und jede CTX-Nummer einmal im Browser öffnen, bevor sie in Schritt 1 geht.

## Schritt 1: Regel-Prompt

Ziel: Die KI liest das Bulletin oder den Bericht für dich und liefert die neuen Zeilen als Patch.
1. `ns_quickcheck_rules_prompt.md` öffnen, den Prompt-Block (zwischen den ``` ) kopieren, in ein neues Chat-Fenster einfügen; nicht in den Recherche-Chat, getrennte Rollen.
2. Block 0: CTX-Nummer oder URL. Kann der Chat Webseiten abrufen, holt er den Text. Sonst im Browser öffnen, den Abschnitt mit Builds oder Indikatoren kopieren, als Block 0 einfügen.
3. Block 1: der Inhalt von `ns_quickcheck.rules` (damit die KI weiß, was schon abgedeckt ist) und darunter der Inhalt deiner `ns_quickcheck.rules.custom`.
4. Block 2 und 3 leer lassen. Absenden. Die KI stellt bis zu drei Fragen; "Standard" antworten, wenn die Annahmen passen.

Erwartet: zuerst die Extraktionstabelle (Builds, Fix-Builds, Bedingung, je mit Zitat) oder die Indikatortabelle (Erstautor, URL, Datum), dann A bis E, darunter der Patch-Block B mit `CVE_TABLE:`- und `IOC:`-Zeilen.

Häufigster Fehler: Dateien unvollständig eingefügt, weil das Chat-Fenster abgeschnitten hat. Prüfen: Die letzte Zeile des eingefügten Blocks ist `IOC` oder `CVE`.

## Schritt 2: Ausgabe prüfen

Ziel: Keine Zahl und kein Wert ohne Beleg.
1. Fix-Builds: Neben jeder Build-Nummer steht ein Zitat aus dem Bulletin; das Zitat muss die Nummer enthalten. Fehlt es oder steht "nicht genannt", die Zahl nicht übernehmen. Die KI "vervollständigt" gern (aus 73.46 wird 73.47, weil es plausibel klingt).
2. Indikatoren: Jede `IOC:`-Zeile hat sechs Felder; das sechste ist die URL des Erstautors (in der Datei kommt beim Anwenden der Regelstand als siebtes Feld dazu) (Behörde, Hersteller des Berichts, Hersteller-Blog). Eine Zusammenstellung (Community-Scanner, Sammelseite) ist keine Fundstelle; solche Zeilen muss die KI mit `PRUEFEN` markiert haben, sie bleiben inaktiv. Zwei Stichproben: URL öffnen, Wert auf der Seite suchen.
3. Vorschläge für Logmuster (C) nicht übernehmen; sie gehören zu ceterion (Issue, Schritt 7).

## Schritt 3: Patch anwenden

Ziel: Deine Custom-Datei plus die neuen Zeilen; nichts von Hand editieren.
1. Patch-Block B in eine Datei `ns_quickcheck.rules.patch` im Werkzeugordner speichern (Texteditor, kein Word). Erste Zeile `# rules-patch 1  <Quelle>  <Datum>`.
2. Im Terminal, im Werkzeugordner: `sh docs/rules-apply.sh ns_quickcheck.rules.custom ns_quickcheck.rules.patch`
3. Das Script sichert deine Custom-Datei als `ns_quickcheck.rules.custom.bak_<alter Stand>`, prüft jede neue Zeile (Format, Fundstelle, keine Dublette), setzt `CUSTOM_VERSION` und schreibt die Datei. Bricht eine Prüfung ab, bleibt die Datei unverändert. Bewertet die Regeldatei dieselbe CVE anders, sagt das Script es ("beide werden geprüft, das strengere Ergebnis zählt").

Erwartet: `== Format-2-Lint ok`, `== Syntax ok`, dann "ns_quickcheck.rules.custom aktualisiert, Sicherung: ...", `CUSTOM_VERSION` und Hash.

Häufigster Fehler: `ERROR Format 2: IOC-Zeile ohne 6 Felder oder Fundstelle`: Die KI hat eine Fundstelle weggelassen. Zeile ergänzen oder streichen, erneut ausführen.

## Schritt 4: Prüfungen verstehen

- **Format-2-Lint**: nur erlaubte Zeilen, Fundstelle je Indikator, gültige CVE-Zeilen, keine Dubletten, keine Shell-Konstrukte. Beschreibung in `docs/rules-format-2.md`.
- **Syntax**: `sh -n`; die Datei muss sich laden lassen.
- Testlogs und Fixtures laufen für die Custom-Datei nicht; sie prüfen die Muster der Regeldatei, die du nicht änderst. Deine Prüfung ist der Lauf auf der Appliance.

## Schritt 5: Lauf auf einer Appliance

Ziel: Die neue Custom-Datei im echten Lauf sehen, bevor sie überall liegt.
1. Hochladen per SCP (WinSCP: Modus Binary) nach `/var/nssnapshot/ns_quickcheck.rules.custom` auf einer Lab- oder HA-Appliance. Rechte: `chown root:wheel`, `chmod 600`.
2. Lauf: `sh /var/nssnapshot/ns_quickcheck.sh --no-out`
3. Kopfzeile: `[INFO] Custom-Datei des Betreibers geladen: <n> aktive Indikator-Zeile(n), <m> CVE-Zeile(n) (<CUSTOM_VERSION>)`. Fehlt sie: Dateiname, Ordner oder Rechte prüfen. Bei abweichenden Fix-Builds folgt eine zweite INFO-Zeile mit beiden Werten.
4. Block 1: Custom-Zeilen sind mit `[custom]` markiert. Verdict mit dem letzten Lauf vergleichen; neues Rot aus einer Custom-Zeile ist das erwartete Ergebnis, wenn der Build unter dem neuen Fix liegt.

Häufigster Fehler: Datei mit Windows-Zeilenenden; auf der Appliance `tr -d '\r' < ns_quickcheck.rules.custom > x && mv x ns_quickcheck.rules.custom`, Rechte neu setzen.

## Schritt 6: Verteilen

1. Dieselbe Datei auf jede Appliance nach `/var/nssnapshot/`, Rechte wie oben. `ns_quickcheck.rules`, `.conf`, `.whitelist` und `.anon.map` nicht anfassen.
2. Lauf je Appliance; `CUSTOM_VERSION` und `custom_sha256` aus der `RESULT`-Zeile in `hosts.md` deines Betreiberordners.

## Schritt 7: Zurück ins Repo (freiwillig)

Zeilen mit Zitat oder Erstautor-URL kannst du als Issue "Indikator" oder "Neues Bulletin" einreichen; ceterion prüft und nimmt sie in den nächsten Regelstand. Danach hast du die Zeile doppelt (Regeldatei und Custom); identische Zeilen werden einmal geprüft, das ist unschädlich. Werte, die nur du nutzen darfst, und Feldbefunde kommen nie in ein Issue. Logmuster-Vorschläge ebenfalls als Issue, nie in die Custom-Datei.

## Konten-Befunde

Block 4 meldet Angriffe auf Gateway-Konten in fester Reihenfolge; die Antwort je Befund:

| Befund | Antwort | Frist |
|---|---|---|
| Treffer (Rot) | Konto sperren, Passwort zurücksetzen, `kill aaa session -userName <konto>`, dann den Nutzer fragen, ob er es war | sofort |
| Brute Force auf ein Konto | Konto und Inhaber prüfen (MFA, woher der Name bekannt ist), Adressen in die Sperrliste, Lockout erwägen (README 15, Howto Lockout) | heute |
| Maschinen und Netze, Schläfer | Netze an der Firewall sperren und in `ns_quickcheck.blocked_ips` eintragen; der nächste Lauf zeigt "Sperre greift nicht", falls nicht | mit dem nächsten Firewall-Change |
| unklar, ein Konto in kurzem Burst | Helpdesk: Nutzer anrufen, Client oder gespeichertes Passwort erneuern | bei Gelegenheit |
| eigene oder interne Adressen | System hinter der Adresse benennen (ns.conf-Objekt oder Netzplan), Konto prüfen | diese Woche |

Kontonamen stehen nur im Original-Report; die anon-Fassung maskiert sie. Die Schwellen dazu: README 4.2 und 4.3.

## Neuer Regelstand von ceterion

Ein neuer Regelstand erscheint als Release mit Tag `rules-<datum>` (nur die Regeldatei) oder zusammen mit einem Script-Release `v17.x`.
1. `ns_quickcheck.rules` vom Release laden, SHA-256 gegen die Release-Seite prüfen.
2. Nach `/var/nssnapshot/` kopieren, Rechte `root:wheel`, 600; die alte Datei wird ersetzt. Custom-Datei, Sperrliste, Whitelist, Config und Zuordnungstabelle bleiben.
3. Ein Lauf; die Kopfzeile zeigt `regeln=<datum>`. Meldet sie "Regeldatei ist aelter als der Mindeststand dieses Scripts", ist die Reihenfolge verdreht: erst die Regeldatei, dann das Script. Ein altes Script läuft mit neuer Regeldatei; ein neues Script lässt mit alter Regeldatei einzelne Prüfungen mit INFO aus.
4. Steht eine deiner Custom-Zeilen jetzt auch in der Regeldatei, die Custom-Zeile entfernen (identische Zeilen sind harmlos, abweichende Fix-Builds ergeben eine INFO).

## Sperrliste

Was du an Firewall, Blocklist oder Appliance gesperrt hast, trägst du in `ns_quickcheck.blocked_ips` ein (Vorlage `ns_quickcheck.blocked_ips.example`): `adresse_oder_netz ; seit ; Bemerkung`. Der Quickcheck zeigt Befunde zu diesen Adressen als ORANGE "abgedeckt", wenn die Beobachtung vor dem Sperrdatum liegt, und als GELB "Sperre greift nicht", wenn die Adresse danach wiederkommt. Die Datei bleibt bei dir; die Bemerkung steht nur im Original-Report. Aufbau der Datei und die Regeln dazu: `ns_quickcheck_README.md`, Abschnitt 5.4.

## Whitelist: mit Hash je Datei

Die Whitelist gibt Dateien frei, nicht Ordner: je Datei genau der geprüfte Stand mit seinem SHA-256. Verzeichnisregeln werden vom Script noch unterstützt, aber nicht empfohlen (siehe ACHTUNG unten); Code (`.js`, `.php`, `.pl`, `.sh`, `.cgi`, `.py`, `plugins.xml`) decken sie ohnehin nie ab.

Ablauf nach einem Befund "Web-Dateien seit Boot":
1. Vorgang zuordnen (Ticket, Deploy-Protokoll). Ohne Vorgang keine Freigabe; dann "Zu tun" Schritt 3 des Befunds.
2. Diff gegen die Vorversion (Snapshot-Set oder Backup); bei Code jede Zeile lesen.
3. Pin-Zeilen erzeugen und anhängen:
   ```
   sh /var/nssnapshot/ns_quickcheck.sh --pin /var/netscaler/logon/LogonPoint_workspace/custom/ >> /var/nssnapshot/ns_quickcheck.whitelist
   ```
   Ergebnis, eine Zeile je Datei:
   ```
   webfile:^/var/netscaler/logon/LogonPoint_workspace/custom/script\.js$@sha256=4c0e8d1f3b7a2c9e5d6f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d
   webfile:^/var/netscaler/logon/LogonPoint_workspace/custom/strings\.de\.js$@sha256=b7d2e4f6a8c0d2e4f6a8c0d2e4f6a8c0d2e4f6a8c0d2e4f6a8c0d2e4f6a803ee
   ```
   `--pin-all` statt `--pin` nimmt auch Bilder, CSS und JSON, wenn der Ordner klein ist und jede Änderung gemeldet werden soll.
4. Kommentarzeile mit Datum und Ticket darüber, Lauf wiederholen, Befund weg.
5. Nach dem nächsten Update meldet der Lauf "per Hash freigegebene Web-Datei erneut geändert" mit den Dateinamen; Schritt 2 und 3 nur für diese.

**ACHTUNG, drei Dinge, die eine Whitelist gefährlich machen:**

1. **Ein Pin ist eine Freigabe für genau diesen Inhalt.** Wer eine Datei pinnt, ohne sie vorher gegen die Vorversion verglichen zu haben, kann eine bereits manipulierte Datei freigeben; ab dann meldet kein Lauf sie mehr, auch nicht der Collector. Deshalb: erst Diff (Snapshot-Set oder Backup), bei Code jede Zeile lesen, erst dann `--pin` oder `--pin-all`. Im Zweifel nicht pinnen.
2. **Eine Dateiregel ohne Hash (`...$` ohne `@sha256=`) gibt den Namen frei, nicht den Inhalt.** Die Datei kann danach beliebig oft geändert werden, der Lauf schweigt. Für Code ist diese Form seit 17.34 wirkungslos; für Bilder, CSS und JSON ist sie erlaubt, aber `--pin-all` ist die bessere Wahl.
3. **Verzeichnisregeln (`.../`) nicht verwenden.** Sie geben alles darunter frei, auch Dateien, die es heute noch nicht gibt. Seit 17.34 deckt eine Verzeichnisregel keinen Code mehr ab, aber eine neue Bilddatei mit Nutzlast im Theme-Ordner bleibt unsichtbar. Bestehende Verzeichnisregeln durch Pins ersetzen: `--pin-all <theme-ordner>` nach dem Diff, die Verzeichnisregel löschen. Die Kopfzeile des Laufs zählt Verzeichnisregeln als INFO.

Prüfen, ob die Whitelist noch stimmt: `grep -c '@sha256=' ns_quickcheck.whitelist` gegen `grep -c '^webfile:' ns_quickcheck.whitelist`; die Differenz sind Regeln ohne Hash.

Was der Hash leistet: Er bindet die Freigabe an einen Inhalt, nicht an einen Namen. Ein Angreifer, der eine freigegebene Datei überschreibt, erzeugt einen Befund; mit einer Verzeichnisregel täte er das nicht. Regelformen und Pflege im Detail: `ns_quickcheck_README.md`, Abschnitt 15, Howto Whitelist.

## Reports und Weitergabe

Jeder Lauf schreibt Original (`.txt`, `.json`, `_ips.tsv`) und anonymisierte Fassung (`_anon.txt`, `_anon.json`). Nach außen (Issue, Ticket, Recherche-Prompt, ceterion) geht nur die anonymisierte Fassung, nach Stichprobe; die Zuordnungstabelle `ns_quickcheck.anon.<host>.map` bleibt auf der Appliance. Weitere Logauszüge vorher mit `sh ns_quickcheck.sh --anon <datei>` behandeln.

Format der Regeldatei und der Custom-Datei: `docs/rules-format-2.md` (verbindlich für Script und Collector).

## Regeln, die immer gelten

- Eine Zusammenstellung Dritter ist ein Hinweis, wo man nachlesen muss, keine Quelle. Fundstelle ist immer die Veröffentlichung des Erstautors.
- Die Custom-Datei nimmt auf, was du nutzen darfst. Dass ein Wert dort steht, macht ihn nicht erlaubter.
- Testlogs und Fixtures nie auf eine Appliance kopieren.
- Kein Report, Bundle oder Log ohne Anonymisierung nach außen.

## Wenn etwas fehlschlägt

- `rules-apply.sh` bricht ab: Meldung lesen, sie nennt die Zeile; Custom-Datei ist unverändert.
- Custom-Datei wird nicht geladen: `ls -l`, Rechte 600, Name genau `ns_quickcheck.rules.custom` im Ordner der Regeldatei.
- Appliance meldet Rot nach dem Einspielen: Einordnung nach den "Zu tun"-Zeilen im Report; nicht die Zeile aus der Custom-Datei löschen, bevor klar ist, was sie getroffen hat.
- Shell stürzt ab ("Segmentation fault"): die Custom-Datei ist selten der Grund; Script-Version prüfen, Issue mit `sh -x`-Trace.

## Pflege durch ceterion

Die Regeldatei folgt demselben Ablauf gegen `ns_quickcheck.rules` (`sh docs/rules-apply.sh ns_quickcheck.rules ns_quickcheck.rules.patch`, Sicherung `ns_quickcheck.rules.bak_<Stand>`), zusätzlich mit Präfix-Prüfung, Testlogs, Fixtures, Herkunftsprotokoll und `docs/release.sh` vor jedem Release.
