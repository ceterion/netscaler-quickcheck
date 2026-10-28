# Changelog

Deutsch und führend. Englische Fassung: [CHANGELOG.md](CHANGELOG.md), spätestens zum Release nachgezogen. Release Notes je Release (englisch, zugleich Text des GitHub-Releases): `docs/releases/`. Das Regel-Changelog `ns_quickcheck.rules.changelog.md` wird nur deutsch geführt.

## Geplant (V18)

- Stock-Manifest je Build (Hashes aller Web- und Management-Dateien aus einer frischen Installation; Block 5 unterscheidet Stock, veränderte Stock-Datei und neue Datei; löst das Whitelist-Pflegeproblem)
- Adress-Feed aus Share-Dateien der Betreiber (Collector: Dedupe, Zwei-Appliances-Regel, Verfall, Abuse-Prozess)
- `WEBSHELL_NAME_RE`: Webshell-Namen als Muster über die Web-Verzeichnisse statt exakter Pfade; Anlass Zscaler 16.10. (`Nx_<nummer>.php/.pl/.html`, Nummer je Angriffsinstanz anders)
- "Neu gegenüber dem letzten Lauf": Befunde, die seit n Läufen unverändert bestehen, als bekannt markieren; nur Neues oben
- `--language en` mit Nachrichtenkatalog; englische Hauptdoku
- Shell-Logs (`bash.log`, `sh.log`) mit `SHELL_CMD_RE`, nur mit Whitelist aus echten Zeilen
- `--compare` mit Hash-Diff statt mtime, Cron und `httpd.conf` im Vergleich
- Stock-Listen und Stock-Hashes für 13.1 und FIPS

## v17.43 (2026-10-28)

Leere Boot-Cores (INFO) zählen nicht mehr als Core-Beleg; ohne Ereignis kein Gelb-Block.

## v17.42 (2026-10-28)

Cores: komprimierte Dateien dem Ereignis zugeordnet; Verzeichnis-Cores `/var/core/<n>` leer und kurz nach Boot als INFO (`CORE_BOOT_LEVEL`), sonst Gelb; Verdict-Satz zur Mitigation nur bei offener CVE; Regelstand 2026-10-28e mit Stock-Hash 73.49. Freeze.

## v17.41 (2026-10-28)

Abstürze: jedes Ereignis mindestens Gelb; Rot bei nsaaad mit SAML ab dem zweiten Ereignis am Tag, httpd bei offenem PHP2Shell, nsppe mit DTLS, drei Ereignissen eines Prozesses am Tag, demselben Prozess an drei Tagen (`ns_quickcheck_observed_crashes.tsv`), Anfrage von außen in den 120 s davor (`crash_trigger`). Neue Belege: Apache-Worker-Abstürze (`HTTPERR_CRASH_RE`), Core ohne Logzeile, Kernel-Panic (`KERNEL_PANIC_RE`), Speicherdruck (`KERNEL_MEM_RE`), Neustart ohne Befehl. `crashes=` in RESULT. Regelstand 2026-10-28d.

## v17.40 (2026-10-28)

Pitboss-Prozesszeilen (`proc <name> (<pid>) SIGNALED` / `EXITED with status 0x8b`) im Ereignis, Signal aus dem Exit-Status; Ereigniszeiten einheitlich aus dem Syslog-Kopf (Lokalzeit). Regelstand 2026-10-28c.

## v17.39 (2026-10-28)

Prozessabstürze: Restart-Zähler je Ereignis, Core-Belege als Dateien `/var/core/<proc>-<pid>` und Verzeichnisse, je Ereignis angehängt; Regelstand 2026-10-28b mit drei weiteren Pitboss-/Kernel-Zeilenarten aus dem Lab.

## v17.38 (2026-10-28)

Verdict nennt offene CVEs, Bulletins und Ziel-Build; `vuln96` nur noch CTX697096, neues Feld `vuln_open`; Anmelde-Zusammenfassung mit Konto je Quelle; Anonymisierung maskiert Hostnamen aus URLs und NT-/DNS-Domänen aus Config-Werten (Lab-Lauf: StoreFront-URL und Domäne standen im Klartext).

## v17.37 (2026-10-28)

CVE-Tabelle: Fix-Build `pending` (kein Fix-Build veröffentlicht, jeder Build des Trains verwundbar), `rules-apply.sh` 2.5, Format 2 1.4. Research-Prompt v17 (Fix-Builds nur aus dem CTX-Artikel, `pending`, "Updated On" lesen), Regel-Prompt v8 (echter Schnitt auf Format 2). Kleinkram: Testlog-Platzhalter `1.1.1.1` ersetzt, `docs/testdata/README.md` ohne gelöschte Stände, Runbook Schritt 7 nur Citrix-IoC-Scan, `release.sh` räumt Zuordnungstabellen vor der Laufdatei-Prüfung.

## v17.36 (2026-10-27)

Regelstand 2026-10-28: Fix-Builds für PHP2Shell (CTX697263, Update vom 27.10.) auf 14.1-73.49, 13.1-64.32, 14.1-FIPS 73.49, 13.1-FIPS 37.286 korrigiert; die Stände 2026-10-23 und 2026-10-27 hatten die Fix-Builds des SAML-Bulletins eingetragen und Appliances auf 73.41 bis 73.46 fälschlich als gefixt gemeldet. Fixtures für gefixte Appliances auf 73.49.

Zeitstempel je Web-Datei über perl (awk-`strftime` fehlte auf der Appliance), Plattform-Lint 4 gegen GNU-awk-Funktionen; Verzeichnisregeln der Whitelist nicht empfohlen (INFO im Kopf, ACHTUNG-Block in WORKFLOW beider Sprachen, Vorlage nur mit Pins).

## v17.35 (2026-10-27)

`--pin-all <pfad>` (Pin-Zeilen für alle Dateien, nicht nur Code); WORKFLOW beider Sprachen mit Abschnitt "Whitelist: mit Hash je Datei".

## v17.34 (2026-10-27)

Whitelist mit drei Regelformen (Verzeichnis `/`, Datei `$`, Datei mit Pin `$@sha256=`); Verzeichnisregeln decken keinen Code ab, Dateiregeln auf Code nur mit Pin; WARN nur noch für Regeln, die keiner Form entsprechen. `--pin <pfad>` erzeugt Pin-Zeilen. Web-Dateien mit Änderungszeit, vollständig im Report, ab 20 je Verzeichnis gruppiert. Zuordnungstabelle übergeht ungültige `user`-/`mail`-Einträge beim Laden. README 15 Howto Whitelist als Fünf-Schritte-Anleitung, Vorlage neu.

## v17.33 (2026-10-27)

Anonymisierer: Konten unter 3 Zeichen und reservierte Reportwörter kommen nicht in die Zuordnungstabelle (vorher machte ein Konto `info` aus `[INFO]` ein `[userNNN]`, ein Konto `-` ersetzte jeden Bindestrich). Web-Dateien: Einordnung über alle geänderten Dateien statt nur die angezeigten; ausführbare Dateien nie als Theme-Anpassung, eigener Hinweis "Diff gegen Vorversion". Whitelist: Hash-Pin `webfile:<regex>@sha256=<hash>`, WARN bei Regeln ohne `$`, Kopfzeile "Whitelist: nicht vorhanden". Zeitspanne der Sondierung chronologisch. Fixture `aaa-dup` (Doppelzählung über `ns.log` und `messages` ausgeschlossen).

## v17.32 (2026-10-27)

Selbsttreffer beseitigt: `nsprofmon_mgmt.pl`-Zeilen (CPU-Momentaufnahmen mit den Kommandozeilen von grep und perl des Quickcheck samt Suchmustern) werden beim Lesen der Syslog-Familie abgezweigt und nur noch mit `SUSPECT_PROC_RE` geprüft; identische Zeilen aus `ns.log` und `messages` zählen einmal. Block 4 zeigt deshalb weniger Treffer als 17.31, nicht weil weniger passiert. Prozessabstürze generisch als Ereignisse je Prozess und PID (Pitboss, Kernel, `/var/core/<n>`), Regelstand 2026-10-27 mit verankerten Mustern; nsaaad wie bisher bewertet, httpd mit Bezug CTX697263, nsppe mit DTLS Rot. Anonymisierte Adresslisten (`_ips_anon.tsv`, `ns_quickcheck_observed_ips_anon.tsv`) und Share-Datei `_share.tsv` für die Weitergabe an ceterion (belastbare Kategorien, keine Appliance-Kennung). Testlog `pitboss-crash.log`, Fixture `crash`.

## v17.31 (2026-10-27)

Vertrauensliste `ns_quickcheck.trusted_ips` (`adresse ; bis ; Bemerkung`, `--trusted`): vertraute Adressen gelten bei Management, SSH und Anmeldefehlern als intern, fallen aus Versuchs-Befunden heraus und erscheinen gesammelt als `[TRUST]` in Blau ohne Verdict-Wirkung (`TRUST_LEVEL=yellow` macht Gelb daraus); Wirkungs-Befunde bleiben Rot. Ablaufdatum, Konflikt mit der Sperrliste als WARN, einmaliges Gelb beim Wechsel von Angreifer- zu Vertrauensliste, `trusted_<art>` in den Adresslisten, `trusted_seen=` in RESULT, Liste `trust` im JSON. Fußzeile mit Werkzeug, Version, Regelstand und Quelle (`FOOTER=1` Vorgabe), `source_url` im JSON. Fixture `trusted`.

## v17.30 (2026-10-23)

CTX697263 (PHP2Shell, CVE-2026-109618 und 109619 im Management-Portal), Regelstand 2026-10-23. Script: `vuln63` in RESULT; Block 2 zeigt Management-Adressen und die Citrix-Mitigation (DENY-ACLs auf Port 80/443, `MGMT_ACL_RE`); Block 4b prüft PHP-Speicher- und Fatal-Muster auch im `admin_ui` (`HTTPERR_PHP_ANOMALY_RE`, Schwelle `PHP_ANOMALY_MIN`): INFO auf gefixtem Build, Gelb auf verwundbarem, Rot mit neuer PHP-Datei im Fenster (Block 5). Heuristik, keine veröffentlichte Signatur. Testlog `httperror-php.log`, Fixture `php2shell`. Bestehende Prüfungen unverändert.

## v17.29 (2026-10-21)

Erstes Release nach dem zurückgezogenen v15.1; Regelstand 2026-10-22b. Die Einzelschritte 17.0 bis 17.29 stehen im Kopf des Scripts, die Release-Notes in `docs/releases/`.

**Regeldatei und Herkunft**
- Regeldatei Format 2: jede Indikatorzeile trägt Quelle, Veröffentlichungsdatum, Fundstelle beim Erstautor und Regelstand; Zeilen ohne Fundstelle sind inaktiv. Verbindliche Beschreibung `docs/rules-format-2.md`, Lint in `rules-apply.sh` und `release.sh`
- Herkunftsprotokoll `ns_quickcheck.rules.provenance.csv/.md`, aus der Regeldatei erzeugt bei jedem Release
- Regelstand 2026-10-20: nur belegte Werte (111 Indikatoren, 40 CVE-Zeilen); Zusammenstellungen Dritter gelten als Verweis, nicht als Quelle
- Werte aus Blöcken Dritter eines Community-Checkers entfernt (siehe Regel-Changelog 2026-10-19); `CREDITS.md` neu, README-Abschnitt Credits

**Custom-Datei des Betreibers**
- `ns_quickcheck.rules.custom` neben der Regeldatei, additiv geladen, nie verteilt, bleibt beim Update; IOC-Block und CVE-Block; identische Zeilen einmal, abweichende beide, das strengere Ergebnis zählt; Kopfzeile und RESULT (`custom`, `custom_sha256`, `cve_custom`, `cve_conflict`)
- `docs/rules-apply.sh` 2.3: `<ziel> <patch>` sichert als `<ziel>.bak_<stand>` und aktualisiert an Ort und Stelle; Dubletten, Fundstelle, CVE-Zeilen geprüft; Hinweis bei Abweichung zur Regeldatei
- WORKFLOW beider Sprachen neu: Betreiber pflegt Indikatoren und Fix-Builds in der Custom-Datei

**Reports, Anonymisierung, Adressen**
- Terminal zeigt alles, was in den Report geht; `--brief` für die Kurzfassung
- Je Lauf anonymisierte Fassung (`_anon.txt`, `_anon.json`, Dateiname mit Ersatzhost) nach Zuordnungstabelle `ns_quickcheck.anon.<host>.map`: Adressen, Hosts, User, Domains, Objektnamen, Themes; `--anon <datei>` für Logauszüge
- 17.12: `--anon` auch für `ns.conf`: Geheimnisse hinter Secret-Parametern, Passwort-Hashes, SNMP-Communities werden ohne Tabelle `***`; FQDNs, Zertifikatsdateien, DN-Komponenten, Server-Namen in der Zuordnungstabelle; Kommentarzeilen reduziert
- Adressliste je Lauf (`_ips.tsv`, im JSON `observed_ips`) und kumuliert je Appliance (`ns_quickcheck_observed_ips.tsv`)
- JSON je Befund `text` und `details`, `mitigation_hits`
- Erklärzeilen je Befund; 17.17: Befundblöcke mit festen Beschriftungen (Wann, Ergebnis, Download-Host oder Adresse mit Sperrliste, Regeldatei und Adressliste, Quelle, Zu tun) für Injection, Dropper-Anfragen und Web-Dateien; vor RESULT die Adressen dieses Laufs mit Status gegenüber dem Bestand und Sperrliste; Quelle beim Treffer auf Payload-Pfad

**Bewertung**
- 17.16: Sperrliste im Format `adresse ; seit ; Bemerkung`, Befundtext "Sperre ab DATUM", Bemerkung nur im Original-Report; Datumsroutine in perl (BWK-awk kennt keine Intervalle, Plattform-Lint 3), nicht bestimmbares Datum heißt "Abdeckung nicht prüfbar"
- 17.15: Sperrliste akzeptiert Zeilen ab zwei Feldern (wo als Freitext, Datum optional), meldet übergangene Zeilen; Fix: Kommentarreduktion der ns.conf-Anonymisierung löschte die Kopfzeile der anon-Reports
- 17.13: Sperrliste des Betreibers `ns_quickcheck.blocked_ips` plus ACLs der Appliance; Befunde zu gesperrten Adressen vor dem Sperrdatum werden ORANGE "abgedeckt" statt Rot, Requests nach dem Sperrdatum GELB "Sperre greift nicht", aktive Verbindungen bleiben Rot; Adresslisten mit Spalte gesperrt, RESULT `orange=` und `blocked_seen=`, JSON-Liste `orange`; Fixture `blocked`
- 17.11: Dropper-Block erkennt Dropper-Suche (mehr als zwei verschiedene Paketnamen von einer Adresse oder Kommandozeichen im Query-String) und meldet Rot statt Gelb; Detaillisten in Terminal und Report vollständig, `DETAIL_MAX` in der Config begrenzt bei Bedarf
- Verdict-Vokabular `OK`, `UPDATE`, `INVESTIGATE`, `FORENSICS_FIRST`
- Fix: SAML-abhängige CVE (CVE-2026-107406) setzte `vuln79` nicht; Fix: `EOL_RELEASES` wurde nie ausgewertet; Fix: IP-Indikatoren trafen als Teilstring; `OUTRE` mit Grenzen

**Betrieb**
- Fix 17.10: BSD-sed kennt `\t` nicht; kumulierte Adressliste blieb auf der Appliance leer, "Verwundbar"-Zeilen fehlten im JSON. Umgestellt auf awk und printf, Plattform-Lint 2 dagegen
- Arbeitsverzeichnis `$BASE_DIR/tmp` statt `/tmp` (Root-Dateisystem lief bei `--compare` voll), Platzprüfung, konfigurierbar `WORK_BASE`
- Optionen mit Wert brechen ohne Wert mit Exit 3 ab
- Fixture-Gate prüft RESULT-Felder; Fixtures `eol` und `custom`; Testlogs im echten httpaccess-Format und Negativtest

**Dokumentation**
- README neu (Schnellstart, Verdict-Entscheidungstabelle, Optionen, Sicherheitsbetrachtung, FAQ, Glossar); unversionierte Dateinamen im Repo, Versionen im Dateikopf; Regel-Changelog beginnt mit dem ersten veröffentlichten Regelstand

## v15.1 (2026-10-19, Release zurückgezogen; Anlass siehe Regel-Changelog, Eintrag 2026-10-19)

Erstes öffentliches Release. Script V15.1 (validiert auf 14.1-73.41 und 14.1-73.46), Regeldatei 2026-10-16b.

- 15.1: httpd.conf mit mtime abseits der Boot-Zeit ist nur noch ROT, wenn der Inhalt einen Befund hat (Alias in Gateway-Pfade, PHP-Handler oder -Flags); sonst GELB mit Hinweis auf Installation oder Upgrade. Fehlalarm beim Abnahmelauf am 19.10. auf der frischen 14.1-73.46 vom 14.10.: `installns` hatte httpd.conf um 10:38 geschrieben, die Datei wird nicht bei jedem Boot neu erzeugt, der Inhalt war sauber, das Verdict trotzdem FORENSICS_FIRST

- Regeldatei: alle acht CVEs aus CTX697096 mit Bedingungen im Bulletin-Wortlaut, CTX697174, CTX697191; 153 Adressen, 19 Domains, 38 Hashes, Payload-Pfade aus Unit 42, CERT-EU, LevelBlue, watchTowr, SOCRadar, einem Community-Checker (MIT, seit 2026-10-19 nicht mehr verwendet) und cisagov/SIGMA_Rules 261399 r1; vorbereitete Variablen `SCANNER_IP_RE` und `PAYLOAD_HASHES` für V16
- Tests: `docs/release.sh` mit Plattform-Lint, 29 Testlog-Erwartungen, zwei Fixtures (clean, compromised); Herkunft je Testzeile in `docs/testlogs/herkunft.md`
- Bekannte Lücken (V16): `--anon`, `HTTPD_SUSPECT_RE`, `BACKDOOR_USER_RE` (`sec_monitor` ist noch fest im Script), Auswertung von `SCANNER_IP_RE` und `PAYLOAD_HASHES`, Portbereiche für Listener, Inhaltsprüfung von Webdateien; Snapshot und Collector folgen als eigene Repos

## 2026-10-16 - Regeln 2026-10-16 bis 2026-10-16b, Recherche-Prompt v11 bis v13, Release-Paket

- Regeldatei 2026-10-16: Payload-Pfade `ns_helper`, `.ns_helper`, `/tmp/.p` (Huntback, via Community)
- Regeldatei 2026-10-16b: cisagov/SIGMA_Rules hat die Regel am 13.10. als 261399 r1 neu veröffentlicht (modified 2026-10-07); 209 Keywords abgeglichen, neu 4 Hashes, 7 Pfade, Dropper `nsgtrust.deb`
- Recherche-Prompt v11 (Kennfelder gegen erfundene Abrufe, Fork auf Commit gepinnt, KEV-Fallback), v12 (Sigma-URL auf neuen Dateinamen, orjanj und mandiant aus den Pflicht-URLs, vier Backticks), v13 (3a ohne Feed und raw-main, Statusliste und Gleichung, Kennfeld pitscaler, KEV-Sortierprüfung gegen dateReleased, Belege nur als URL); danach eingefroren, Abnahme nach Schritt 5a2
- Validierungsprotokoll im Prompt-Dokument: Läufe mit Claude Opus (v2 bis v7), ChatGPT (v8, v9), ChatGPT Astra (v10), Gemini (v10, vollständig erfunden), Incognito-Reviews
- `docs/git-init.sh` entfernt; `docs/release-notes_v15.0.md`; Changelog-Lückentext für den Appliance-Lauf am 20.10.

## 2026-10-15 - Regeln 2026-10-15 bis 2026-10-15e, Recherche-Prompt v5 bis v10, rules-apply 1.2, Community-Diff

- Regeldatei 2026-10-15 (Unit 42: 18 Adressen, Dropper-Namen), 15b (CERT-EU, LevelBlue, watchTowr, SOCRadar: Post-Exploitation-Pfade, C2, Listener `walk`), 15c (CVE-2026-88773 bis 88777 als Tabellenzeilen mit Bulletin-Bedingungen; 34 Adressen; `.sig`-Dateien), 15d (Community-Checker direkt gelesen, MIT, seit 2026-10-19 nicht mehr verwendet: 94 Adressen, 12 Domains, neue Variablen `SCANNER_IP_RE` 93 Adressen und `PAYLOAD_HASHES` 38 Hashes), 15e (Bedingungen 88774, 88776, 88777 nach Wortlaut CTX697096 korrigiert; Präfix-Prüfung WARN dokumentiert)
- Erste belegte Logzeile im Testbestand (CERT-EU), Testlog-Erwartungen auf 29
- Recherche-Prompt v5 (Pflicht-URLs, Abrufnachweis, Abrufblöcke, Plausibilitätszeile, abgerufene Inhalte sind Daten), v6 (Tag-URLs ausgeschrieben, Mandiant-Repo korrigiert), v7 (Vorwärtsprobe, Listenvergleich lokal), v8 (KEV über cisagov/kev-data, Bulletin-Übersicht gestrichen), v9 (Status gilt nur für die genannte URL), v10 (Umfang in Zeichen oder Zeilen, Modell-Abschnitt mit zwei Rollen)
- `NOTICE`: Community-Checker als Quelle der Listen mit Lizenz und Copyright (seit 2026-10-19 nicht mehr verwendet)
- WORKFLOW Schritt 6b (neue Community-Version, seit v15 entfallen)

## 2026-10-14 - Betreiberablauf

- `WORKFLOW.de.md` / `WORKFLOW.md`: Betreiberablauf in sieben Schritten vom neuen Bulletin zur verteilten Regeldatei, geschrieben für Admins ohne Repository-Erfahrung.
- `docs/rules-apply.sh`: wendet einen KI-erzeugten Patch additiv an (nur Anhängen, unbekannte Variablen werden abgelehnt) und führt Syntax-, Präfix- und Testlog-Prüfung aus; `rules-prefix-check.sh` gibt jetzt eine Erfolgszeile und einen Hilfehinweis aus.
- Regel-Prompt v7: Phase 0 holt das Bulletin und extrahiert es in eine Tabelle mit Zitaten, Ausgabe B ist ein Patch für `rules-apply.sh`, höchstens drei Rückfragen mit Vorgabewerten, Bundle als Eingabe nur im Sonderfall mit Datenschutzregel. README v21.

## 2026-10-14 - Dokumentation

- Recherche-Prompt v3: Regel-Diffs von SigmaHQ und signature-base, Hash-Abfragen bei VirusTotal, Feldquellen, Quellenregel nach Wirkung im Prompt. README v20: VirusTotal-Abfrage mit Upload-Verbot im Runbook; "Kunde" durchgehend durch "Betreiber" ersetzt. Issue-Vorlagen zweisprachig; Kontaktlinks aus config.yml entfernt (GitHub stellt mailto-Links nicht dar).

## 2026-10-14 - v15.0

- `SECURITY.md`, Issue-Vorlagen (Fehlalarm, übersehener Indikator) und Kontaktadressen ergänzt; v15.0 validiert auf 14.1-73.46 (Lab, online).
- v14.0 validiert auf 14.1-73.46 (Lab, online und offline). Fix: Der Zweig für einen passenden Hash rief eine nicht definierte Ausgabefunktion auf (seit 12.0, sichtbar erst auf einem Build mit Stock-Hash). `docs/release.sh` prüft Ausgabeaufrufe jetzt gegen die definierten Funktionen.

## 2026-10-14 - v14.0, Regeln 2026-10-14b

- v13.0 validiert auf NetScaler 14.1-73.46 (frische Lab-Installation): Fixtures clean und compromised, Online-Lauf, kein Absturz.
- Lab-Befund: `ns_monuploadd_err.pl` wird vom Daemon `/netscaler/monuploadd` aufgerufen (von pitboss überwacht), nicht von cron. v14.0 bewertet den Elternprozess dreistufig (Daemon INFO, cron Gelb, sonst Rot) und meldet Shell- oder Downloader-Kindprozesse des Scripts als Rot. Regeln 2026-10-14b ergänzen `SUSPECT_PROC_PARENT_OK_RE`, `SUSPECT_PROC_CHILD_RE` und den ersten Stock-Hash (`ns_monuploadd_err.pl`, 14.1-73.46).

## 2026-10-14 - v13.0

- `ns_quickcheck.conf` und `ns_quickcheck.whitelist` werden als `.example`-Vorlagen ausgeliefert, damit ein Update keine Betreiberdateien überschreibt; Update heißt nur Script und Regeln. Das Regel-Changelog trägt den SHA-256 des Stands 2026-10-14.
- Fix: SIGSEGV der NetScaler-Shell in Block 5 (Klammergruppe in einer Kommandosubstitution in der System-User-Prüfung, seit 10.0 vorhanden und nie auf einer Appliance gelaufen). Lint in `docs/release.sh` ergänzt, Plattformregel erweitert. Gefunden beim Lauf der Fixtures auf einer Appliance.

## 2026-10-14 - v12.0, Regeln 2026-10-14

- Fixtures `docs/testdata/fixtures/clean` und `compromised` mit erwarteten Verdicts; `docs/release.sh` führt sie nach `--testlog` aus. README 4.1 nennt je Option ein Beispiel mit Standardpfad. Prüfung der Dropper-Pfade hinter die Injection-Erkennung verschoben, damit die rote Stufe greift.
- Regeln 2026-10-14 aus der CISA-SIGMA-Regel CMA_SIGMA_Citrix_CVE_2026_8871 (2026-09-29), Sygnia und Unit 42: `b64decode`, `INDEX:`, `c88771.json`, neu `SUSPECT_PROC_RE`, `DROPPER_PATH_RE`, `STOCK_HASH_FILES`/`STOCK_FILE_HASHES`; Hinweis zu den acht CVEs aus CTX697096.
- v12.0: Prozessprüfung mit Elternprozess (`cron` Gelb, sonst Rot), Anfragen auf Dropper-Pfade je Quelladresse (Gelb, Rot mit Injection), Hashes von Systemdateien (INFO, bis ein Stock-Wert vorliegt). Grundsatz: Empfindlichkeit vor Spezifität, unsichere Stock-Zustände werden Gelb mit Begründung gemeldet.
- Testlogs erweitert (Zeilen von CISA, Unit 42, Sygnia; Grenzfälle bei Namen in `clean.log`; `admin-audit.log`), `--testlog` deckt jetzt `DROPPER_PATH_RE` und `SUSPECT_PROC_RE` ab: 29 PASS.
- Copyright-Vermerk vereinheitlicht auf `Copyright 2026 ceterion AG`, Autor in NOTICE genannt; NOTICE nennt die Indikatorquellen und hält fest, dass kein Code Dritter verwendet wurde. Das Regel-Changelog trägt SHA-256 für alle archivierten Stände.

## 2026-10-13 - v11.0, Regeln 2026-10-09d

- `--testlog`: prüft die Logmuster der Regeldatei gegen `docs/testlogs/` und `expected.txt` (PASS/FAIL, Exit-Code). Pflicht vor jeder Regeländerung; `docs/release.sh` führt es aus.
- `docs/testlogs/`: eine Datei je CVE, `clean.log` als Fehlalarm-Test, `expected.txt`, `herkunft.md` mit Herkunft je Zeile (konstruierte Zeilen markiert, sie werden durch gemeldete oder Lab-Zeilen ersetzt).
- Prompts: Recherche v2 fordert wörtliche Logzeilen mit Quelle; Regeln v6 verlangt je Muster eine Testzeile und eine Erwartung.

Releases: Tag `v<major>.<minor>` für das Script, `rules-<datum>` für die Regeldatei (Konvention bis 2026-10-19; seitdem nur Script-Tags, der Regelstand steht mit SHA-256 im Regel-Changelog). Details je Änderung im Script-Kopf und in `ns_quickcheck.rules.changelog.md`.

## 2026-10-09 - v10.0, Regeln 2026-10-09d (Abspaltung des Repos, nicht veröffentlicht)

- `ns_quickcheck.sh` als unversionierte Kopie von `ns_quickcheck_V10.sh` für den Betrieb, synchron gehalten durch `docs/release.sh`; Regeln 2026-10-09d erlauben den unversionierten Namen in `ALLOWED_CRON_RE`. Dokumentation und Prompts bleiben nur versioniert.
- Repository `netscaler-quickcheck` aus der NetScaler Integrity Baseline herausgelöst; Snapshot und Collector folgen getrennt.
- README v13: zugehörige Repositories mit Funktion, Stand, Roadmap und Schnittstellen; optionale CLI-Ebene ohne Snapshot; Quellenregel für sekundäre Indikatoren.
- Regeln 2026-10-09c: Herkunft der Community-Indikatoren als Sekundärquelle markiert; 2026-10-09b: `72.5.65.111`, `v5v.in`; 2026-10-09: CTX697191 / CVE-2026-107406 mit rollenabhängigen Fix-Builds (SP ab 73.37/64.23, IdP ab 73.46/64.29).
- Prompt v5 und README 7.1: Quellenregel nach Wirkung eines falschen Eintrags (Bulletin nur für Builds und CVE-Zeilen; Quellen mit beobachteter Zeile für Logmuster; Sekundärquellen zulässig für Pfade, Hashes, Adressen, Domains). Recherche-Prompt v1.
- `docs/rules-prefix-check.sh` ersetzt den früheren, fehlerhaften Befehl für die Präfix-Prüfung.

## 2026-10-08 - v10.0 (nicht veröffentlicht)

- 10.0: Befunde eines Abnahmelaufs auf einer Produktivappliance: Passwort-Hashes im Diff zu `ns.conf.0` maskiert, `CLI_USER` automatisch als Service-User zugelassen, Whitelist-Typ `mitigation:`, `--compare cron`. Regeln 2026-10-08e betreiberneutral.
- 5.0 bis 8.0 (Lab, 14.1): Absturz der NetScaler-sh bei `$( { ...; } | ... )` behoben; Stock-Zustände von 14.1 (PHP-Handler, Listener, Aliase, Shell-Audit, Profiler-Zeilen) als Regeln statt als Befunde; Burst-Regel für Web-Dateien; Alias-Prüfung über das Ziel.
- 3.0 und 4.0: CVE-Tabelle in der Regeldatei, Diff zu `ns.conf.0`, Deltas der Hit-Counter, Hash von Script und Regeln, `--ki-bundle` mit Anonymisierung und Selbstprüfung.
- 2.0: Config-Schichtung, Report als Text und JSON, Whitelist, Abgleich der Zeitzone, `--compare`, ausgehende Verbindungen, Hinweis auf den HA-Partner.

## 2026-10-06 - 1.0

- Erste Version: sechs Blöcke, Online- und Offline-Modus, Regeldatei, entschärfte Ausgabe (defanged), RESULT-Zeile, Verdict mit Handlungstext.
