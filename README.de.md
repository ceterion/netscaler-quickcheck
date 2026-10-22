# netscaler-quickcheck

English: [README.md](README.md). Ausführliche Dokumentation und Runbook: `ns_quickcheck_README.md` (deutsch, führend) und `ns_quickcheck_README.en.md` (englisch; zitiert die deutschen Ausgabezeilen mit ihrer Bedeutung). **Sprache:** Die Ausgaben des Scripts (Terminal, Report, Befundtexte im JSON) sind in dieser Fassung bewusst deutsch: Das Werkzeug ist mit und für Betreiber im DACH-Raum entstanden, deren Reports von Administratoren, Geschäftsführung und Prüfern auf Deutsch gelesen werden; ein Sicherheitsbefund, der erst übersetzt werden muss, kostet Zeit in der einen Situation, in der Zeit zählt. Feldnamen, Verdicts und RESULT-Zeile sind sprachneutral und in `docs/report-format.md` englisch dokumentiert, damit Maschinen und nicht deutschsprachige Leser mit einem Report arbeiten können. Eine englische Ausgabe (`--language en`) ist für V18 geplant; Repo-Front, Workflow und Formatdokumente gibt es bereits auf Englisch. Betreiberablauf bei neuem Bulletin: [WORKFLOW.de.md](WORKFLOW.de.md).

Sicherheits-Triage für Citrix NetScaler ADC und Gateway, auf der Appliance: Build gegen die Citrix-Bulletins, Angriffsspuren, Kompromittierungs-Schnellcheck, Adresslisten, anonymisierte Reports, ein Verdict. Regelgesteuert, offline-fähig, erweiterbar durch eigene Indikatoren. Entstanden im Oktober 2026 für CTX697096, CTX697174 und CTX697191, gebaut für die Bulletins danach.

**Stand:** **Validiert auf NetScaler 14.1** (73.41 und 73.46, Lab- und Kundengateways, Oktober 2026). **13.1 und FIPS: Beta.** CVE-Tabelle, Fix-Builds und alle logbasierten Prüfungen (Block 1 bis 4) gelten unverändert; je Train unterschiedlich sind die Stock-Zustände in Block 5 (Listener, Alias-Wurzeln, Admin-Befehlsmuster, Stock-Hashes), die aus 14.1 stammen. Auf 13.1 oder FIPS beim ersten Lauf Gelb in Block 5 und eine INFO "kein Stock-Hash für diesen Build" statt der Hash-Prüfung erwarten; nichts wird unterdrückt, das Verdict bleibt `INVESTIGATE`, bis die Listen erweitert sind. Bestätigte Befunde kommen lokal in die Whitelist; ein anonymisierter Erstlauf-Report (`ns_quickcheck_README.md`, 5.3) an die Kontaktadresse lässt uns die Stock-Listen für alle erweitern. Teil 1 von 3 der NetScaler Integrity Baseline; Snapshot und Collector folgen in eigenen Repositories (siehe Zugehörige Repositories). Vor dem ersten Lauf auf einer neuen Appliance das Abnahme-Protokoll lesen. Versionsgeschichte: `CHANGELOG.md`.

## Warum nicht einfach grep

### Was es findet

- **Den Schläfer finden.** Der Sprayer, der montags vier Konten probiert, pausiert und freitags wiederkommt, bleibt unter jeder Lockout- und Ratenschwelle. Die kumulierte Adressliste sieht die Wiederkehr; der Report nennt es beim Namen.
- **Das Spraying finden.** Dutzende Maschinen, tausend Kontonamen, je ein Versuch: nach /24 gruppiert, mit Takt, Konten und der Frage, auf die es ankommt: ob eine davon hineingekommen ist.
- **Das eine Konto unter Beschuss finden.** Brute Force auf einen Namen ist ein anderer Angriff mit einer anderen Antwort. Er bekommt einen eigenen Befund und ein eigenes "diese Person anrufen".
- **Den Treffer finden.** Eine erfolgreiche Anmeldung nach einer Fehlserie ist Rot, mit Konto, Adresse und den drei Befehlen, die zuerst laufen.
- **Die Sondierung vor der Shell finden.** Anfragen nach bekannten Webshell-Namen in jedem Theme-Ordner, mit der echten Quelle aus dem Access-Log, und eine rote Zeile, falls ein Webshell-Pfad je mit 200 geantwortet hat.
- **Die Lücke finden.** Fehlende Logs, fehlende Regeln, unlesbare Dateien: Das Verdict sagt `INVESTIGATE` und nennt, was es nicht prüfen konnte. Es sagt nie `OK` aus Mangel an Beweisen.
- **Laufende, gespeicherte und vorherige Config vergleichen.** Ungespeicherte Änderungen auf der Appliance sind ein Befund, ebenso eine sicherheitsrelevante Abweichung zwischen `ns.conf` und `ns.conf.0` (neue System-User, Policies, Listener, Management-Zugriff). Ein Angreifer, der die laufende Config ändert, ohne zu speichern, hinterlässt keine Datei für das nächste Backup; diese Prüfung sieht es.

### Wie es arbeitet

- **Entscheiden statt scrollen.** Ein Lauf, ein Verdict, "Zu tun" unter jedem Befund, auf der Appliance, in der FreeBSD-Shell, offline, wenn es sein muss.
- **Nichts anfassen.** Keine Netzverbindung, keine Änderung an Konfiguration oder Systemdateien, kein Agent, kein Python. Das Script liest über die CLI-Ebene mit einem nur lesenden Service-User und schreibt nur in seine eigenen Verzeichnisse. Es läuft während eines Incidents, ohne Teil davon zu werden.
- **Mit gestern vergleichen.** Auf ein Snapshot-Set gerichtet läuft es offline, auch für eine Appliance, die schon neu aufgesetzt ist; mit `--compare` sagt es, was sich seit dem letzten Snapshot geändert hat: Web-Dateien, Cron, Listener, Config. Der tägliche Cron-Lauf plus Snapshot ergibt eine Zeitreihe, und die kumulierte Adressliste gibt jedem Angreifer ein "bekannt seit".
- **Mitigation, die wirklich greift.** Eine Responder-Policy gegen CVE-2026-88771 ist nur etwas wert, wenn sie an den richtigen vServern gebunden ist und ihr Hit-Counter sich bewegt. Das Script prüft die Bindung, liest die Zähler und meldet Treffer seit dem letzten Lauf als eigene Angriffsspur.
- **Nur lesend, von Anfang an.** Die CLI-Ebene läuft unter einem Service-User, den eine Command Policy auf `show` und `stat` begrenzt, ohne `show techsupport` und ohne `show system file`; ein 32-Zeichen-Secret in einer 600-Datei, kein Passwort in Script oder Report. Wer das nicht einrichten kann, lässt das Script ohne diese Ebene laufen; es sagt dann, was es nicht sehen konnte.
- **Deinen Kontext behalten.** Die Sperrliste macht abgedeckte Befunde Orange, die Whitelist nimmt bestätigte Änderungen heraus, eigene Indikatoren stehen in einer Custom-Datei, die jedes Update überlebt.
- **Eigene Fix-Builds, eigene Entscheidung.** Die Custom-Datei kann eigene CVE-Zeilen tragen: einen Hotfix-Build von Citrix, einen Train, den die öffentliche Regeldatei noch nicht kennt. Beide Dateien werden ausgewertet, das strengere Ergebnis gilt, und eine Abweichung zwischen ihnen ist ein Befund, kein stilles Überschreiben.
- **Die Firewall füttern und dann prüfen, ob es hält.** Jeder Lauf schreibt die fremden Adressen, die er gesehen hat, nach Kategorie (Download-Host, Dropper-Anfrage, Sondierungsquelle, Spraying-Maschine, Schläfer, Treffer) in eine Liste je Lauf und eine kumulierte Liste je Appliance: zuerst gesehen, zuletzt gesehen, Tage, Anzahl je Fenster. Was du sperrst, kommt mit Datum in `ns_quickcheck.blocked_ips`; der nächste Lauf markiert abgedeckte Befunde Orange und meldet "Sperre greift nicht" für jede Adresse, die trotzdem noch ankommt.
- **Weitergeben können.** Anonymisierte Fassungen mit stabiler Zuordnung je Appliance; Konten- und Hostnamen maskiert, Angreiferwerte erhalten, Adresslisten nach Kategorie für Firewall und SOC.
- **Zwei Prompts, eine Regeldatei.** Das Repository enthält die zwei Prompts, mit denen die Regeln entstehen: einen Recherche-Prompt, der die Fakten eines Bulletins nur bei Erstveröffentlichern sammelt, mit URL und Datum je Wert, und einen Regel-Prompt, der daraus einen Patch im Format der Regeldatei macht. Jeder kann sie auf das nächste Bulletin oder auf eigene Befunde anwenden, den Patch mit `rules-apply.sh` einspielen und bekommt denselben Lint, dieselbe Herkunftsprüfung und dieselbe Dublettenprüfung wie wir. Die Methode liegt im Repo, nicht nur das Ergebnis.
- **Den Regeln trauen.** Jeder Indikator auf seinen Erstveröffentlicher zurückgeführt, jedes Release durch 54 Testlogs, 6 Fixtures und drei Plattform-Lints; jede Schwelle dokumentiert und einstellbar.

## Was es prüft

Ein Lauf, sechs Blöcke, ein Verdict (`OK`, `UPDATE`, `INVESTIGATE`, `FORENSICS_FIRST`):

- **Build** gegen jede CVE-Zeile der Regeldatei (Fix-Builds je Train, Bedingungen wie SAML oder `tcpParam`), End-of-Life-Trains, ungespeicherte Config.
- **Exposure und Mitigation**: SAML, DTLS, Management-Zugriff auf SNIPs, Responder-Policies mit Hit-Countern.
- **Angriffsspuren** aus den Logs der Appliance: Injection-Versuche in Logon-Zeilen mit Download-Host und Quelle (auch aus Responder-Zeilen), nsaaad-Crashes, Dropper-Anfragen, Webshell-Sondierung und Webshells, die geantwortet haben, Interpreter-Fehler, Management- und SSH-Zugriffe von außen, und Angriffe auf Gateway-Konten: Password Spraying, Brute Force auf einzelne Konten, langsame "Schläfer", eigene Adressen mit Anmeldefehlern und erfolgreiche Anmeldungen nach einer Fehlserie (Rot).
- **Kompromittierungs-Schnellcheck**: Payload-Pfade und Webshell-Namen aus Regeldatei und Custom-Datei, geänderte Web-Dateien außerhalb von Upgrade-Fenstern, Cron, Listener, System-User, verdächtige Prozesse, aktive Verbindungen zu Angreifer-Adressen.
- **Betreiberkontext**: eine Sperrliste (an der Firewall bereits gesperrte Adressen) macht abgedeckte Befunde Orange, eine Whitelist nimmt bestätigte Änderungen heraus, die Schwellen der Kontenprüfungen stehen in einer Config.
- **Ausgaben**: Report, JSON, Adresslisten je Lauf und kumuliert nach Kategorie, anonymisierte Fassungen für die Weitergabe. `coverage=partial` in der RESULT-Zeile heißt, eine Kernprüfung hatte keine Daten; das Verdict ist dann nie `OK`.

Testbasis: 54 Testlogs, 6 Fixtures und drei Plattform-Lints vor jedem Release (`docs/release.sh`). Details: `ns_quickcheck_README.md`, Abschnitte 4.3 (Schwellen) und 6 (Blöcke).

## Schnellstart

Bezug: Die zwei Dateien für eine Appliance, `ns_quickcheck.sh` und `ns_quickcheck.rules`, hängen an jedem Release unter https://github.com/ceterion/netscaler-quickcheck/releases; das Repository selbst wird nur für `--testlog`, die Fixtures und die Regelpflege gebraucht.

```sh
# Appliance, als root. Upload per SCP im Modus Binary.
mkdir -p /var/nssnapshot && cd /var/nssnapshot
cp ns_quickcheck.conf.example ns_quickcheck.conf; cp ns_quickcheck.whitelist.example ns_quickcheck.whitelist   # nur erste Einrichtung
chown root:wheel ns_quickcheck* && chmod 700 ns_quickcheck.sh && chmod 600 ns_quickcheck.conf ns_quickcheck.rules ns_quickcheck.whitelist
sh ns_quickcheck.sh                 # volle Ausgabe auf dem Bildschirm, Report und JSON unter /var/nssnapshot/quickcheck/
echo EXIT=$?                        # 0 OK, 1 INVESTIGATE, 2 UPDATE oder FORENSICS_FIRST, 3 Abbruch (Grund auf stderr)
```

Zuerst die letzten Zeilen lesen: `ACTION:` und die `RESULT`-Zeile. Exit 1 oder 2 ist ein Verdict, kein Fehler; was zu tun ist, steht unter jedem Befund. Nur wenn der Lauf ohne `RESULT`-Zeile abbricht, mit Trace wiederholen (`sh -x ns_quickcheck.sh --no-out 2>/tmp/qc_trace.txt >/tmp/qc_out.txt`) und beide Dateien, mit `--anon` anonymisiert, an die Kontaktadresse senden.

Vor der ersten Abnahme, am Arbeitsplatz: `sh ./ns_quickcheck.sh --from ./docs/testdata/fixtures/compromised --hours 100000 --no-out` muss mit `ACTION: FORENSICS_FIRST` enden, `fixtures/clean` mit `ACTION: OK`; `sh ./ns_quickcheck.sh --testlog ./docs/testlogs/` muss 0 FAIL melden.

Optionen (jede Option mit Wert auch als `--option=wert`; ohne Wert Abbruch mit Exit 3):

| Option | Wert | Wirkung |
|---|---|---|
| `--hours` | Stunden | Logfenster, Dateien der letzten n Stunden (Vorgabe 144) |
| `--from` | Pfad | Offline-Lauf gegen ein entpacktes Snapshot-Set |
| `--compare` | `cron`, `latest` oder Pfad | Vergleich gegen das jüngste vollständige Set, das jüngste Set oder ein entpacktes Archiv 1 |
| `--rules` | Pfad | Regeldatei; `ns_quickcheck.rules.custom` wird daneben gesucht |
| `--whitelist` | Pfad | Whitelist je Appliance |
| `--conf` | Pfad | Konfigurationsdatei, wird vor allen anderen Optionen geladen |
| `--out` | Pfad | Reportdatei; JSON, Adressliste und anon-Fassungen daneben |
| `--no-out` | | nur Bildschirm, keine Dateien |
| `--anon` | Datei | beliebigen Logauszug mit der Zuordnungstabelle dieser Appliance anonymisieren, Ausgabe auf stdout, sonst nichts |
| `--full`, `--brief` | | alles auf dem Bildschirm (Vorgabe) oder nur Befunde |
| `--no-cli` | | CLI-Ebene auslassen |
| `--testlog` | Ordner oder Datei | Regelmuster gegen Testlogs prüfen (Arbeitsplatz, nie Appliance) |
| `--ki-bundle` | | anonymisiertes Material für die Regelpflege (nur Abnahme) |
| `--version` | | Version ausgeben |

Abnahme auf einer neuen Appliance: jede rote und gelbe Zeile lesen und einordnen als Stock-Zustand des Builds, Betreiberkonfiguration oder Befund; Stock-Zustände kommen in `ns_quickcheck.rules` (mit Herkunftszeile und Changelog), Betreiberkonfiguration in `ns_quickcheck.whitelist`; zweiter Lauf. Details: `ns_quickcheck_README.md`, Abschnitt 7a. Beim ersten Lauf sind zwei bis fünf Regel- oder Whitelist-Einträge je Appliance-Typ zu erwarten.

## Dateien

**Update einer eingerichteten Appliance:** nur `ns_quickcheck.sh` und `ns_quickcheck.rules` kopieren. `ns_quickcheck.conf` und `ns_quickcheck.whitelist` gehören dem Betreiber und sind nie Teil eines Updates; das Repository liefert sie als `.example`, damit ein unachtsames `cp *` sie nicht überschreibt.

Alle Dateien tragen unversionierte Namen; die Version des Scripts steht im Header und in der `RESULT`-Zeile, die von README und Prompts in ihren ersten Zeilen. Versioniert sind nur die Release Notes (`docs/release-notes_v<version>.md`).

| Datei | Zweck |
|---|---|
| `ns_quickcheck.blocked_ips.example` | Vorlage für die Sperrliste des Betreibers (an Firewall, Blocklist oder Appliance bereits gesperrte Adressen); Befunde zu gesperrten Adressen vor dem Sperrdatum werden ORANGE "abgedeckt", Requests nach dem Sperrdatum GELB "Sperre greift nicht" |
| `ns_quickcheck.rules.custom.example` | Vorlage für eigene Indikatoren des Betreibers (gleiches Format wie der IOC-Abschnitt); als `ns_quickcheck.rules.custom` neben die Regeldatei kopieren, wird additiv geladen, nie verteilt und beim Update nicht ersetzt |
| `<BASE_DIR>/tmp/` | Arbeitsverzeichnis für Zwischendateien und das Entpacken bei `--compare` (konfigurierbar `WORK_BASE`); nie `/tmp`, das auf NetScaler auf dem kleinen Root-Dateisystem liegt |
| `ns_quickcheck_observed_ips.tsv` | kumulierte Liste der beobachteten fremden Adressen je Appliance, je Lauf fortgeschrieben; `grep -v '^#' ns_quickcheck_observed_ips.tsv | cut -f2 | sort -u` liefert die reine Adressliste |
| `ns_quickcheck_<host>_<zeit>_ips.tsv` | beobachtete fremde Adressen des Laufs je Kategorie (Download-Host im Payload, Injection-Quelle, Dropper-Anfrager, ausgehender Treffer) mit Anzahl, für Firewall-Blocklisten nach Prüfung; im JSON als `observed_ips` |
| `ns_quickcheck.anon.<host>.map` | Zuordnungstabelle je Appliance für die anonymisierten Reports (`_anon.txt`, `_anon.json`, bei jedem Lauf); bleibt auf der Appliance, wird nie verteilt. `--anon <datei>` anonymisiert beliebige Logauszüge mit derselben Tabelle |
| `ns_quickcheck.rules.provenance.md` | Herkunftsprotokoll aus der Regeldatei: Quelle, Veröffentlichungsdatum und Fundstelle je Wert |
| `ns_quickcheck.conf.example` | Vorlage für die optionale Konfiguration (Fenster, Reportverzeichnis, CLI-Ebene); einmal als `ns_quickcheck.conf` auf die Appliance |
| `ns_quickcheck.rules` | CVE-Tabelle, Angriffsmuster, Payload-Pfade, Angreifer-Adressen, Stock-Zustände je Build; eine Datei für alle Betreiber |
| `ns_quickcheck.rules.changelog.md` | jede Regeländerung mit Bulletin, Zitat, Test und Verteilung |
| `ns_quickcheck.whitelist.example` | Vorlage für Ausnahmen je Appliance (Konten, Listener, Pfade, Cron, Theme-Dateien, eigene Mitigation-Policies); einmal als `ns_quickcheck.whitelist` auf die Appliance |
| `ns_quickcheck_README.md` | vollständige Dokumentation und Runbook |
| `ns_quickcheck_rules_prompt.md` | Prompt für die KI-gestützte Regelpflege: holt und extrahiert das Bulletin, liefert einen Patch für `docs/rules-apply.sh`; Bundle nur als Sonderfall |
| `ns_quickcheck_research_prompt.md` | Prompt für einen getrennten Recherche-Chat: Bulletins, Indikatoren, Diffs der Community-Tools, Fehlalarme |
| `docs/rules-prefix-check.sh` | prüft, dass ein Regel-Update nur angehängt hat |
| `docs/rules-apply.sh` | wendet einen KI-erzeugten Regel-Patch additiv an und führt Syntax-, Präfix- und Testlog-Prüfung aus |
| `WORKFLOW.de.md`, `WORKFLOW.md` | Betreiberablauf in sieben Schritten vom Bulletin zur verteilten Regeldatei (deutsch, englisch) |
| `docs/release.sh` | erzeugt `ns_quickcheck.sh` aus dem versionierten Script, Lint, `--testlog`, Fixture-Läufe |
| `docs/PLATFORM.de.md` | Plattformbefunde: Absturz der NetScaler-`sh` bei Klammergruppen in `$( )`, Stock-Listener, Aliase, Logformate |
| `docs/testdata/` | Regeldatei-Stände für Prompt-Abnahmetest und Präfix-Prüfung; `fixtures/clean` und `fixtures/compromised` für den vollen Offline-Lauf mit erwarteten Verdicts (`fixture-expected.txt`), nie auf eine Appliance kopieren |
| `SECURITY.md`, `.github/ISSUE_TEMPLATE/` | Meldewege und Issue-Vorlagen für Fehlalarme und übersehene Indikatoren |
| `docs/testlogs/` | Testlogs je CVE plus `clean.log`, `admin-audit.log`, `expected.txt`, `herkunft.md`; Lauf mit `--testlog`, nie auf eine Appliance kopieren |

## Zugehörige Repositories

| Repository | Funktion | Stand | Roadmap | Schnittstelle zum Quickcheck |
|---|---|---|---|---|
| `netscaler-snapshot` (eigenes Repository, folgt) | täglicher Datei-Snapshot je Appliance: vier Archive, Manifest mit Zeitstempeln und SHA-256, Zustand von Prozessen, Listenern, Cron und laufender Config über einen read-only Service-User, normalisierter Diff laufende gegen gespeicherte Config | V7, Lab-validiert auf 14.1-73.41 | Pull-Transport vom Collector, Quickcheck-Reportverzeichnis in Archiv 1, Blocklisten-Modus bei Bedarf | `--from` und `--compare` lesen entpackte Sets; `CLI_USER` und Secret kommen aus `ns_snapshot.conf` |
| `netscaler-collector` (eigenes Repository, folgt) | PowerShell-7-Collector: Sets prüfen, idempotent importieren, Tagesdiff mit Klassifizierung und Filtern, Report als Ampel, IoC-Nachscan über 90 Tage | V2, Schritt 1 von 3 (Import), mit synthetischen Sets getestet | Schritt 2 Compare, Schritt 3 Report und Alarmierung, Verschlüsselung at rest, Pull-Transport | liest `quickcheck/*.json` als Ampelbeitrag, sobald der Snapshot das Verzeichnis mitnimmt |

Der Quickcheck läuft ohne beide: ohne Snapshot mit eigener `ns_quickcheck.conf` und, ohne Service-User, mit der gespeicherten Config (Option A). CLI-Ebene und Service-User: `ns_quickcheck_README.md`, Abschnitt 3.1.

## Service-User für die CLI-Ebene

Optional, empfohlen: Ein Read-only-Service-User gibt dem Quickcheck Hit-Counter, Deny-List, aktive Sessions und den Diff der laufenden Config. Läuft `netscaler-snapshot`, wird dessen User automatisch mitgenutzt; sonst einmalig je Appliance einrichten wie in `ns_quickcheck_README.md`, Abschnitt 3.1 beschrieben (Command Policy nur `show` und `stat`, nur CLI, eine Session, Secret-Datei 600 unter `/var/nssnapshot/`).

## Bekannte Grenzen

- Musterbasiert. `OK` heißt: Build gefixt, kein bekannter Indikator getroffen, keine Spuren im Fenster. **Es heißt nicht, dass die Appliance sauber ist**; ein Angreifer mit Pfaden oder Namen, die noch niemand veröffentlicht hat, bleibt für jede regelbasierte Prüfung unsichtbar. War die Appliance vor dem Fix exponiert, den IoC-Scan des Herstellers als unabhängige zweite Meinung laufen lassen: die Funktion "Indicators of Compromise" der NetScaler Console (https://docs.netscaler.com/en-us/netscaler-console-service/instance-advisory/ioc) oder, ohne Console, den Scanner des Citrix Supports über ein Ticket.
- Report- und Befundtexte sind in dieser Fassung bewusst deutsch: Das Werkzeug ist mit und für Betreiber im DACH-Raum entstanden, deren Reports von Administratoren, Geschäftsführung und Prüfern auf Deutsch gelesen werden; ein Befund, der erst übersetzt werden muss, kostet Zeit in der einen Situation, in der Zeit zählt. Feldnamen, Verdicts und RESULT-Zeile sind sprachneutral (`docs/report-format.md`). Englische Ausgabe (`--language en`) ist für V18 geplant.
- Das Script findet, was veröffentlicht ist; ein leerer Block 5 ist kein Freispruch. Vollständige Liste in `ns_quickcheck_README.md`, Abschnitt 12.
- Stock-Zustände unterscheiden sich je Build-Familie. Auf 13.1 oder FIPS beim ersten Lauf Fehlalarme erwarten, bis die Stock-Listen erweitert sind (Issue).
- Die NetScaler-`/bin/sh` stürzt bei einer Klammergruppe in einer Kommandosubstitution ab; `docs/release.sh` prüft darauf (`docs/PLATFORM.de.md`).
- Die Anonymisierung ersetzt, was `ns.conf` kennt oder privat ist; fremde Hostnamen und Benutzernamen in Logzeilen bleiben Klartext. Stichprobe vor Weitergabe.
- Die Custom-Datei kann die Bewertung nur strenger machen; neue Prüfmuster brauchen ein Update der Regeldatei.
## Mitwirken

Autor und Maintainer: Jens Miltenberger, ceterion AG, seit 2004 mit Citrix-Appliances befasst, vom Net6 Access Gateway über die Übernahme von NetScaler durch Citrix bis zu den heutigen ADC- und Gateway-Builds. Siehe CREDITS.md.


Kontakt: netscaler-integrity@ceterion.com für Fragen und Abnahmen; Sicherheitsdefekte im Script an security@ceterion.com (siehe `SECURITY.md`), nie als öffentliches Issue.

Issues und Pull Requests sind willkommen. Regeländerungen müssen additiv sein, eine Herkunftszeile (`# +<Datum> <Quelle>: <was>`) und einen Changelog-Eintrag tragen. Quellenregel nach Wirkung: Build-Nummern und CVE-Zeilen nur aus dem Citrix-Bulletin; Logmuster nur aus Quellen, die die beobachtete Zeile zeigen, gegen echte Logs getestet; Pfade, Hashes, Adressen und Domains auch aus Sekundärquellen, dann so markiert. Jedes neue Logmuster bringt eine Testzeile in `docs/testlogs/` und eine Erwartung in `expected.txt` mit; `sh ns_quickcheck.sh --testlog docs/testlogs/` muss bestehen. Shell-Änderungen müssen POSIX sh sein und auf einem NetScaler getestet werden. Mit einem Beitrag stimmst du den Bedingungen der Apache License 2.0 für deinen Beitrag zu (Abschnitt 5).

## Credits

Indikatordaten stammen von den jeweiligen Veröffentlichern, die in der Regeldatei je Zeile genannt sind (Citrix, CISA, CERT-EU, Unit 42, LevelBlue, watchTowr, SOCRadar und weitere). Siehe [CREDITS.md](CREDITS.md).

## Lizenz

Apache License 2.0, siehe `LICENSE` und `NOTICE`. Bereitgestellt "AS IS", ohne Gewährleistung irgendeiner Art; siehe `DISCLAIMER.md` (deutsch und englisch). Ein Verdict dieses Werkzeugs ersetzt weder eine forensische Untersuchung noch eine Aussage des Herstellers.

Copyright 2026 ceterion AG.
