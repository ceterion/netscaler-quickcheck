#!/bin/sh
# =============================================================================
# ns_quickcheck.sh
# Copyright 2026 ceterion AG
# SPDX-License-Identifier: Apache-2.0
#
# Bereitgestellt "AS IS", ohne Gewaehrleistung oder Garantie irgendeiner Art, ausdruecklich oder
# stillschweigend, einschliesslich Marktgaengigkeit und Eignung fuer einen bestimmten Zweck. Nutzung
# auf eigene Verantwortung. Ein Verdict dieses Werkzeugs ersetzt keine forensische Untersuchung und
# keine Aussage des Herstellers. Haftung im gesetzlich zulaessigen Umfang ausgeschlossen.
# Siehe LICENSE und DISCLAIMER.md im Repository.
#
# Provided "AS IS", without warranty of any kind, express or implied, including merchantability and
# fitness for a particular purpose. Use at your own risk. A verdict of this tool does not replace a
# forensic investigation or a vendor statement. Liability excluded to the extent permitted by law.
# NetScaler ADC / Gateway - Sicherheits-Triage auf der Appliance: ein Lauf, ein Verdict. Entstanden fuer CTX697096,
# CTX697174 und CTX697191, gebaut fuer die Bulletins danach.
#
# Version : 18.0 (2026-10-30)
# Autor   : ceterion AG, Jens Miltenberger
# Plattform: NetScaler 13.1 / 14.1 (FreeBSD), /bin/sh. Offline auch Linux/macOS/WSL.
# Dateien : ns_quickcheck.conf (optional), ns_quickcheck.rules, ns_quickcheck.whitelist (optional)
#           ns_snapshot.conf wird fuer CLI_USER / CLI_SECRET_FILE / CLI_TIMEOUT mitgelesen.
#
# Bloecke
#   1 Build (gefixt / verwundbar / EoL / gestaged, Config gespeichert?)
#   2 Exposure (SAML, DTLS, Enhanced ISN, Partitions, Management auf SNIP)
#   3 Mitigation (Policies gebunden und wirksam, Hit-Counter, Deny-List)
#   4 Angriffsspuren der letzten N Stunden, Quell-IPs mit Zeitzonen-Abgleich, Download-Hosts
#   5 Kompromittierung (Payload-Pfade, Webshells, Persistenz, Listener, ausgehende Verbindungen,
#     ungespeicherte Config-Aenderungen, optional Vergleich gegen den letzten Snapshot)
#   6 Verdict: OK / INVESTIGATE / UPDATE / FORENSICS_FIRST mit Handlungstext, HA-Peer-Hinweis
#
# Aufruf
#   sh ns_quickcheck.sh                       online, Report als Datei plus anonymisierte Fassung, alles auf dem Bildschirm
#   sh ns_quickcheck.sh --brief               nur Befunde und Kurzzeilen auf dem Bildschirm (Report bleibt vollstaendig)
#   sh ns_quickcheck.sh --hours 24
#   sh ns_quickcheck.sh --compare latest      zusaetzlich gegen das juengste Snapshot-Set in out/
#   sh ns_quickcheck.sh --compare cron        gegen das juengste vollstaendige Set (status=complete)
#   sh ns_quickcheck.sh --testlog docs/testlogs/   Regel-Muster gegen Testlogs pruefen (Arbeitsplatz, nie Appliance)
#   sh ns_quickcheck.sh --compare /pfad       gegen ein entpacktes Archiv 1 (manifest/, state/)
#   sh ns_quickcheck.sh --anon /var/log/ns.log.1 > /var/tmp/ns.log.1.anon
#                                                 beliebigen Logauszug mit der Zuordnungstabelle dieser Appliance
#                                                 anonymisieren (Ausgabe auf stdout), fuer Issues und den Recherche-Prompt
#   sh ns_quickcheck.sh --anon=/var/tmp/auszug.txt    gleiche Option in der Schreibweise mit Gleichheitszeichen
#   sh ns_quickcheck.sh --blocked /pfad/ns_quickcheck.blocked_ips   Sperrliste an anderem Ort (Vorgabe: neben dem Script)
#   sh ns_quickcheck.sh --anon /nsconfig/ns.conf > /var/tmp/ns.conf.anon   ns.conf fuer Support oder Issue: Geheimnisse werden ***
#   sh ns_quickcheck.sh --from /pfad          offline gegen entpackte Archive 1 (+3)
#   sh ns_quickcheck.sh --no-cli              CLI-Ebene aus
#   sh ns_quickcheck.sh --no-out              keine Reportdateien
#   sh ns_quickcheck.sh --out /pfad/datei     Reportdatei an anderem Ort (JSON daneben)
#   sh ns_quickcheck.sh --rules / --whitelist / --conf <datei>
#   sh ns_quickcheck.sh --ki-bundle           anonymisiertes Bundle (gekuerzte Regeln, Logzeilen) fuer den KI-Prompt
#   sh ns_quickcheck.sh --lang en             englische Ausgabe (Katalog ns_quickcheck.msg.en neben dem Script; Config LANG_QC)
#   sh ns_quickcheck.sh --pin <verzeichnis>   Pin-Zeilen fuer die Whitelist (Code-Dateien, --pin-all alle Dateien)
#
# Reihenfolge der Konfiguration: Defaults, ns_snapshot.conf (nur CLI_*), ns_quickcheck.conf,
# Kommandozeile. Jede Datei nur, wenn root-owned und nicht group/world-writable.
#
# Verhalten: read-only, keine Named Pipes, Log- und Payload-Zeilen immer defanged.
# Exit-Codes: 0 OK, 1 INVESTIGATE, 2 UPDATE oder FORENSICS_FIRST, 3 Fehler
#
# Changelog
#   18.0  2026-10-30 Nachrichtenkatalog: alle Report-, Terminal- und Dateitexte liegen in ns_quickcheck.msg.<sprache>
#                    (KEY<TAB>Text, Platzhalter %1..%9) neben dem Script; --lang de|en (Config LANG_QC), Vorgabe de;
#                    fehlende Keys fallen auf de zurueck und werden im Kopf gezaehlt. Jeder Befund traegt den Key als
#                    code im JSON. Kennungen ([OK] ... [TRUST]) kommen aus dem Katalog, Spaltenbreite wird berechnet.
#                    Deutsche Ausgabe byteidentisch zu 17.44 (release.sh prueft gegen Referenzreports).
#   17.44 2026-10-30 Vier Fehler aus der Katalog-Durchsicht: Sperrdatum in der Injection-Quellenliste doppelt ("ab
#                    2026-10-202026-10-20"); Verdict bei offener SAML-CVE nannte "Ziel: 14.1-." ($FIXB nie gesetzt, jetzt
#                    FIXMAX); toter Mitigation-Satz im INVESTIGATE-Zweig entfernt; --compare filterte die Whitelist auf Zeilen
#                    mit vorangestelltem NEU/GEAENDERT, verankerte webfile-Regeln griffen nicht.
#   17.43 2026-10-28 Boot-Cores (INFO) zaehlen nicht mehr als Core-Beleg; ohne Ereignis kein Gelb-Block ("0 Ereignisse,
#                    1 Beleg" beim Betreiber). Core-Belegliste ohne Boot-Cores.
#   17.42 2026-10-28 Cores: komprimierte Dateien (<proc>-<pid>.gz) werden dem Ereignis zugeordnet statt als Phantom-
#                    Ereignis gezaehlt; nummerierte Verzeichnisse /var/core/<n> gelten als Verzeichnis-Core (Prozess
#                    unbekannt): leer und innerhalb 15 min nach Boot = INFO "Boot-Nachlauf" (CORE_BOOT_LEVEL=info, Vorgabe;
#                    yellow macht Gelb daraus), sonst Gelb als Ereignis. Verdict: Mitigation-Satz nur bei offener CVE.
#                    Regelstand 2026-10-28e: Stock-Hash 14.1-73.49 (Lab und Betreiber). Freeze.
#   17.41 2026-10-28 Abstuerze, Linie "lieber mehr": jedes Ereignis mindestens Gelb; Rot bei nsaaad mit SAML ab dem zweiten
#                    Ereignis in 24 h, httpd bei offenem PHP2Shell, nsppe mit DTLS-Fehlern, jedem Prozess ab drei Ereignissen
#                    in 24 h, demselben Prozess an drei Tagen (kumulierte Datei ns_quickcheck_observed_crashes.tsv), und bei
#                    einer SAML-Anfrage oder einem externen Management-Request in den 120 s vor dem Absturz (Adresse als
#                    crash_trigger in die Adresslisten). Neue Belege: Apache-Worker-Abstuerze im Fehlerlog (HTTPERR_CRASH_RE),
#                    Core-Datei ohne Logzeile, Neustart ohne reboot/shutdown im Audit-Log, Kernel-Panic (KERNEL_PANIC_RE),
#                    Speicherdruck (KERNEL_MEM_RE). crashes=<n> in RESULT und JSON. Regelstand 2026-10-28d.
#   17.40 2026-10-28 Prozessabstuerze: Zeilen des Pitboss-Prozesses selbst ("proc <name> (<pid>) SIGNALED" / "EXITED with status
#                    0x8b") werden dem Ereignis zugeordnet; das Signal wird aus dem Exit-Status (128 + n) abgeleitet, wenn
#                    keine Kernel-Zeile vorliegt (Regelstand 2026-10-28c, Lab 28.10.).
#   17.39 2026-10-28 Prozessabstuerze: Restart-Zaehler je Ereignis (aus der folgenden "New pid"-Zeile) statt Hoechstwert je
#                    Prozess; Core-Belege als Dateien /var/core/<proc>-<pid> und Verzeichnisse /var/core/<n>, je Ereignis an
#                    die Zeile gehaengt; neue Zeilenarten "collecting core dump on", "Adding pitboss watch", Kernel "Core dump
#                    of pid" (Regelstand 2026-10-28b, Lab 28.10.).
#   17.38 2026-10-28 Verdict nennt die offenen CVEs und Bulletins mit Ziel-Build (bisher fest CTX697096 und leeres Ziel);
#                    vuln96 nur noch fuer CTX697096-Zeilen, neues RESULT-Feld vuln_open=<n> (Zahl offener CVEs); Anmelde-
#                    Zusammenfassung mit Konto je Quelle; Anonymisierung liest Hostnamen aus URLs und Domaenen aus
#                    -ntDomain/-domain/-dnsSuffix/-searchFilter in ns.conf-Werten (Lab-Lauf 28.10.: StoreFront-URL und
#                    NT-Domaene standen im Klartext in der anon-Fassung).
#   17.37 2026-10-28 CVE-Tabelle: Fix-Build "pending" = Hersteller hat noch keinen Fix-Build veroeffentlicht; jede Appliance
#                    des Trains gilt als verwundbar, Befund nennt "Fix-Build noch nicht veroeffentlicht (Stand <Regelstand>)".
#                    Anlass: CTX697263 hatte vom 22. bis 27.10. keinen Fix-Build; der Regelstand 2026-10-23 trug die Builds
#                    eines anderen Bulletins ein. Mit pending waere der Fehler nicht moeglich gewesen (Format 2, 1.4).
#   17.36 2026-10-27 Zeitstempel je Web-Datei ueber perl statt awk-strftime (BWK-awk kennt strftime nicht, die Zeiten
#                    fehlten auf der Appliance); Kopfzeile zaehlt Verzeichnisregeln der Whitelist als INFO (nicht empfohlen,
#                    Pins je Datei verwenden). Plattform-Lint 4 gegen GNU-awk-Funktionen.
#   17.35 2026-10-27 --pin-all <pfad>: Pin-Zeilen fuer alle Dateien unter dem Pfad (nicht nur Code), fuer die Whitelist mit
#                    Hash je Datei (WORKFLOW, Abschnitt Whitelist).
#   17.34 2026-10-27 Whitelist mit drei Regelformen: Verzeichnis (endet mit /; deckt nie Code ab), Datei (endet mit $),
#                    Datei mit Pin ($@sha256=<hash>, Pflicht fuer Code: .js .php .pl .sh .cgi .py plugins.xml). WARN nur noch
#                    fuer Regeln, die keiner Form entsprechen, und fuer Dateiregeln auf Code ohne Pin. --pin <pfad> gibt
#                    fertige Pin-Zeilen fuer alle Code-Dateien darunter aus. Web-Dateien: Report listet alle nicht freigegebenen
#                    Dateien mit Aenderungszeit (neueste zuerst), Terminal 8 plus "n weitere"; ab 20 Dateien je Verzeichnis
#                    gruppiert (Code bleibt einzeln). Zuordnungstabelle: user-/mail-Eintraege unter 3 Zeichen oder mit
#                    Reportwoertern werden beim Laden uebergangen (INFO), Tabelle bleibt unveraendert.
#   17.33 2026-10-27 Anonymisierer: Konten unter 3 Zeichen und reservierte Woerter (OK, INFO, WARN, GELB, ROT, ORANGE, TRUST,
#                    ACTION, RESULT, user, root, nsroot u. a.) kommen nicht in die Zuordnungstabelle; Benutzer "-" nie.
#                    Web-Dateien: Einordnung ("Ergebnis") ueber alle geaenderten Dateien statt nur ueber die angezeigten;
#                    ausfuehrbare Dateien (.js, .php, .pl, .sh, .cgi, plugins.xml) nie als Theme-Anpassung, eigener Hinweis
#                    "ausfuehrbarer Code, Diff gegen Vorversion". Whitelist: optionaler Hash-Pin webfile:<regex>@sha256=<hash>
#                    (Treffer nur bei gleichem Hash, sonst "freigegebene Datei erneut geaendert"), WARN bei webfile-Regeln
#                    ohne abschliessendes $; Kopfzeile "Whitelist: nicht vorhanden". Zeitspanne der Webshell-Sondierung
#                    chronologisch. Regressionstest AAA mit duplizierten Zeilen (Fixture aaa-dup).
#   17.32 2026-10-27 Anonymisierte Adresslisten (_ips_anon.tsv je Lauf, ns_quickcheck_observed_ips_anon.tsv kumuliert:
#                    ohne Hostname, Bemerkungen der Sperr- und Vertrauensliste entfernt) und Share-Datei _share.tsv fuer
#                    die Weitergabe an ceterion (nur belastbare Kategorien, keine Appliance-Kennung). Selbsttreffer und Prozessabstuerze: nsprofmon_mgmt.pl-Zeilen (CPU-Momentaufnahmen, die den eigenen
#                    grep und perl des Quickcheck samt Suchmustern loggen) werden beim Lesen der Syslog-Familie abgezweigt
#                    und nur noch mit SUSPECT_PROC_RE geprueft; identische Zeilen aus ns.log und messages zaehlen einmal
#                    (catns). Prozessabstuerze generisch: Pitboss- und Kernel-Zeilen (PITBOSS_RE, KERNEL_EXIT_RE, Regel-
#                    stand 2026-10-27) werden zu Ereignissen je Prozess und PID mit Signal, Restart-Zaehler und Core-
#                    Verzeichnis /var/core/<n> im Fenster; nsaaad wie bisher bewertet (Gelb, Rot mit SAML und offener
#                    SAML-CVE), httpd Gelb mit Bezug CTX697263, nsppe mit DTLS-Fehlern Rot, andere INFO. Altes Muster als
#                    NSAAAD_CRASH_LEGACY_RE: Treffer nur dort ergeben INFO "unbekanntes Format". Core-Verzeichnisse auch
#                    ohne Logzeile (Rotation). Hinweis: Block 4 zeigt gegenueber 17.31 weniger Treffer, weil die
#                    Selbsttreffer wegfallen, nicht weil weniger passiert.
#   17.31 2026-10-27 Vertrauensliste ns_quickcheck.trusted_ips (adresse ; bis ; Bemerkung) oder --trusted <pfad>:
#                    vertraute Adressen gelten bei Management, SSH und Anmeldefehlern als intern, fallen aus Versuchs-
#                    Befunden heraus (Sondierung, Dropper, Spraying, Brute Force, Schlaefer) und erscheinen gesammelt
#                    als [TRUST] in Blau ohne Verdict-Wirkung (TRUST_LEVEL=trust|yellow); Wirkungs-Befunde bleiben Rot
#                    mit Zusatz. Ablaufdatum, Konflikt mit der Sperrliste als WARN, einmaliges Gelb beim Wechsel von
#                    Angreifer- zu Vertrauensliste, Kategorie trusted_<art> in den Adresslisten, trusted_seen= in RESULT,
#                    Liste trust im JSON. Fusszeile mit Werkzeug, Version, Regelstand und Quelle (FOOTER=1 Vorgabe,
#                    FOOTER=0 schaltet ab), source_url im JSON.
#   17.30 2026-10-23 CTX697263 (PHP2Shell, CVE-2026-109618/109619 im Management-Portal): vuln63 in RESULT; Block 2 zeigt
#                    die Management-Adressen (NSIP, SNIPs mit mgmtAccess) und ob die von Citrix empfohlenen DENY-ACLs auf
#                    Port 80/443 existieren (MGMT_ACL_RE); Block 4b prueft PHP-Speicher- und Fatal-Muster im Webserver-
#                    Fehlerlog auch im admin_ui (HTTPERR_PHP_ANOMALY_RE, Schwelle PHP_ANOMALY_MIN): INFO auf gefixtem Build,
#                    Gelb auf verwundbarem, Rot mit neuer PHP-Datei im Fenster. Heuristik, keine Signatur.
#   17.29 2026-10-21 AAA: Schlaefer (Fehlversuche an AAA_SLEEPER_DAYS Tagen im Fenster oder laut kumulierter Liste,
#                    oder Spanne von AAA_SLEEPER_DAYS Tagen, mehrere Konten, nie Maschinen-Takt) als eigener Befund, Adressliste aaa_sleeper; Anmeldefehler von
#                    eigenen Adressen (ns.conf, RFC 1918, MGMT_NET_RE) als eigener Befund mit ns.conf-Objekt, nie in
#                    Adresslisten. Reihenfolge: Treffer, Brute Force, Schlaefer, Spraying, intern.
#   17.28 2026-10-21 Kumulierte Adressliste ohne Summe: anzahl_zuletzt, zuletzt_fenster_h, anzahl_max, max_fenster_h
#                    (die Summe zaehlte dieselben Logzeilen je Lauf erneut). Spraying: Adressen aus /24-Netzen mit
#                    mindestens zwei Maschinen gelten als "Angriff (Netz)"; ein Konto mit kurzem Burst wird als
#                    moeglicher Client mit altem gespeichertem Passwort benannt.
#   17.27 2026-10-21 Kumulierte Adressliste zaehlt Tage statt Laeufe (ein Tag mit zehn Laeufen zaehlt einmal); Spalte
#                    "tage", zuerst/zuletzt als Datum des Laufs. Bestehende Datei: laeufe wird als tage uebernommen.
#   17.26 2026-10-21 Brute Force auf einzelne Konten als eigener Befund (AAA_BF_MIN Fehlversuche auf ein Konto oder
#                    AAA_RATE/min auf ein Konto, Erfolg danach von jeder Adresse = Rot); Spraying-Befund mit Reihenfolge
#                    unklar, dann Maschinen, Nutzer als Zahl; Howto Lockout (set aaa parameter -maxloginAttempts).
#   17.25 2026-10-21 Gateway-Anmeldefehler je Adresse mit Takt, Konten, Zeitraum und "Erfolg danach" (AAA_OK_RE, Fenster
#                    AAA_OK_WIN=5 min, gleiches Konto und Adresse); Bewertung Mensch/Maschine aus Takt und Erfolg; Erfolg
#                    nach Fehlserie einer Maschinen-Adresse = Rot (Treffer). Listen auf 15 Zeilen, Netze oben, angegriffene
#                    Konten; Kontonamen in der anon-Fassung maskiert. Regelstand 2026-10-21d.
#   17.24 2026-10-21 Injection-Quelle bei Responder-Zeilen aus der Zeile selbst ("from IP", Client_ip, CLIENT.IP.SRC),
#                    keine Access-Log-Korrelation mehr fuer Responder-Zeilen (Lab: falscher Kandidat); Hinweis "identisch
#                    mit dem Download-Host". Anonymisierung: Host-Header-Werte (Hostname:, Host:) aus Responder-Zeilen,
#                    sofern kein Angreiferwert. Scriptordner absolut aufgeloest (Zuordnungstabelle immer am selben Ort).
#   17.23 2026-10-21 Validierung (externes Review): Kernvariablen der Regeldatei zur Laufzeit geprueft (Exit 3);
#                    coverage=full|partial in RESULT, fehlende oder unlesbare Logfamilien machen das Verdict nicht OK;
#                    Responder-Korrelation nur Requests mit Status 4xx und als Kandidat benannt (injection_source_candidate);
#                    Domain-Indikatoren mit Grenzen und ohne Gross-/Kleinschreibung; Webshell-Pfad mit Status 200 im
#                    Access-Log = Rot.
#   17.22 2026-10-21 Quellen je /24 zusammengefasst (Sondierung, Dropper); Requests ohne Quelle beziffert; Injection-
#                    Quelle auch bei Responder-Zeilen (jeder Request zur Versuchssekunde); LINE_MAX statt fester 200
#                    Zeichen (Vorgabe 400, 0 = ungekuerzt); Log-Zaehlung der Anmeldungen ohne #nsinternal#; Gateway-
#                    Anmeldefehler (AAA_FAIL_RE, Schwellen AAA_FAIL_IP/AAA_FAIL_USERS); Upgrade-Datum aus nsinstall.log
#                    als Grenze fuer "seit Upgrade geaendert". Regelstand 2026-10-21c.
#   17.21 2026-10-21 Webserver-Fehlerlog in zwei Pruefungen: Interpreter-Fehler (HTTPERR_EXEC_RE, Rot ausserhalb
#                    admin_ui) und Sondierung von Webshell-Namen (HTTPERR_PROBE_RE plus Dateinamen aus PAYLOAD_PATHS,
#                    Gelb, Quellen aus dem Access-Log, Sperrliste, Adressliste webshell_probe, PROBE_LEVEL=info in der
#                    Config); Client ausserhalb 127.0.0.x im Fehlerlog = Gelb "direkt angesprochen". Apache-Datumsformat
#                    in der Datumsroutine. #nsinternal# aus den Anmeldungen. "nicht geprueft" mit genauem Grund;
#                    Mindest-Regelstand RULES_MIN, Hinweis bei aelterer Regeldatei.
#   17.20 2026-10-21 "Log:" zaehlt je Datei die tatsaechlich gefundenen Zeilen (nicht die Rohmuster; notice.log lieferte
#                    Hunderte harmlose Treffer). INFO "nicht geprueft", wenn eine Logfamilie im Fenster fehlt; Kopfzeile
#                    nennt die gelesenen Logfamilien mit Dateizahl.
#   17.19 2026-10-21 Zeile "Log:" je Befund (Datei und Trefferzahl). Neue Logs: httperror.log und httperror-vpn.log
#                    (HTTPERR_RE, PHP-Fehler ausserhalb Stock), httpaccess.log der Management-Ebene (MGMT_PATH_RE, Zugriffe
#                    von aussen, MGMT_NET_RE in der Config), auth.log (AUTH_LOGIN_RE, AUTH_FAIL_RE: Logins von aussen,
#                    Backdoor-Konten, Brute Force), /var/log/cron (letzter Lauf fremder Cron-Zeilen). Regelstand 2026-10-21.
#   17.18 2026-10-21 Adressen in den Befundbloecken ohne [.]-Maskierung (Betreiberwunsch; hxxp in Logzeilen bleibt);
#                    "Wann" der Web-Dateien aus den erfassten Aenderungszeiten statt neuem stat.
#   17.17 2026-10-21 Befundbloecke mit festen Beschriftungen (Wann, Ergebnis, Download-Host/Adresse, Quelle, Zu tun) fuer
#                    Injection, Dropper-Anfragen und Web-Dateien; je Download-Host Sperrliste, Regeldatei und Adressliste.
#                    Vor RESULT die Adressen dieses Laufs mit Status gegenueber dem Bestand und Sperrliste.
#   17.16 2026-10-21 Sperrliste im Format "adresse ; seit ; Bemerkung" (Tabs weiter erlaubt); Befundtext "Sperre ab DATUM";
#                    Bemerkung nur im Original-Report ([Bemerkung: ...] wird in anon-Fassungen entfernt). Datumsroutine in
#                    perl statt awk (BWK-awk kennt keine Intervalle {n,m}); nicht bestimmbares Beobachtungsdatum heisst
#                    "Abdeckung nicht pruefbar", nie Gelb, nie Orange. Plattform-Lint 3 gegen Intervalle in awk.
#   17.15 2026-10-21 Sperrliste: Zeilen ab zwei Feldern gueltig (wo als Freitext, seit optional = nur markiert),
#                    uebergangene Zeilen mit Nummer gemeldet, Kopfzeile auch bei 0 gueltigen Zeilen. Fix: Kommentar-
#                    reduktion der ns.conf-Anonymisierung loeschte die Kopfzeile der anon-Reports.
#   17.14 2026-10-21 Fix Anonymisierung: Hostname blieb in Dateinamen und zusammengesetzten Zeichenketten stehen
#                    (Wortgrenze schloss Unterstrich aus); Hostnamen werden jetzt auch dort und in einem Nachlauf
#                    ueberall ersetzt.
#   17.13 2026-10-21 Sperrliste des Betreibers ns_quickcheck.blocked_ips (Adresse oder Netz, wo, seit, Ticket, Kommentar) plus
#                    ACLs der Appliance: Befunde zu gesperrten Adressen vor dem Sperrdatum werden ORANGE "abgedeckt" statt
#                    Rot; Requests nach dem Sperrdatum sind GELB "Sperre greift nicht"; aktive Verbindungen bleiben Rot.
#                    Adresslisten mit Spalte gesperrt, RESULT orange= und blocked_seen=, JSON-Liste orange.
#   17.12 2026-10-21 Anonymisierung fuer ns.conf: Geheimnisse hinter -encrypted und Secret-Parametern werden *** (ohne
#                    Tabelle), FQDNs aus add server und Monitoren, Zertifikatsdateien, DN-Komponenten aus bindDn/ldapBase,
#                    Kommentarzeilen reduziert; Kopfzeile nennt Anzahl maskierter Geheimnisse.
#   17.11 2026-10-21 Detaillisten vollstaendig in Terminal und Report (DETAIL_MAX in der Config, Vorgabe 0 = alles).
#                    Dropper-Block: mehr als zwei Paketnamen von einer Adresse oder Query-String mit Kommandozeichen hinter
#                    dem Paketnamen = Rot "Dropper-Suche, kein Client" (Lab-Befund 21.10.).
#   17.10 2026-10-21 Fix: BSD-sed kennt \t in der Ersetzung nicht; kumulierte Adressliste blieb auf der Appliance leer und
#                    "Verwundbar"-Zeilen fehlten im JSON. Umgestellt auf awk und printf; Plattform-Lint lehnt \t in sed ab.
#   17.9 2026-10-21  Optionen mit Wert brechen ohne Wert mit Exit 3 ab (vorher stiller Normallauf). Kumulierte Adressliste je Appliance: ns_quickcheck_observed_ips.tsv im Reportverzeichnis, je Lauf
#                    fortgeschrieben (Anzahl gesamt, Laeufe, zuerst/zuletzt gesehen); Terminalzeile nennt neue Adressen
#                    gegenueber dem Bestand. Keine Loeschung durch REPORT_KEEP_DAYS.
#   17.8 2026-10-21  Custom-Datei darf CVE-Zeilen tragen (Block : <<'CVE' ... CVE, Format wie CVE_TABLE). Sie werden
#                    zusaetzlich bewertet, nicht ersetzend: identische Zeilen einmal, abweichende Zeilen beide, das
#                    strengere Ergebnis zaehlt. RESULT: cve_custom, cve_conflict. Zaehler nennt Custom-Anteil.
#   17.7 2026-10-20  Erklaertexte fuer Betreiber ohne Vorwissen: je Befund "Was passiert ist", "Zu tun", "Unkritisch wenn"
#                    als Detailzeilen (Injection auf gefixtem Build, Download-Host, fehlende Quell-IP, Dropper-Anfragen,
#                    Web-Dateien, httpd.conf, nsaaad, Verdict INVESTIGATE). Kopfzeilen der Befunde unveraendert.
#   17.6 2026-10-20  Adressliste je Lauf: ns_quickcheck_<host>_<zeit>_ips.tsv (kategorie, adresse, anzahl, quelle der
#                    Beobachtung) fuer Firewall-Blocklisten; Kategorien payload_download_host, injection_source,
#                    dropper_requester, outbound_hit. Eigene Adressen und RFC-1918 werden nicht aufgenommen. Hinweis
#                    auf Fehlalarmrisiko (NAT, CDN, WARP) im Dateikopf; im JSON als observed_ips.
#   17.5 2026-10-20  Verdict-Vokabular: OK, UPDATE (Build offen oder EoL), INVESTIGATE (Build gefixt, aber Spuren, ISN
#                    offen oder Gelb), FORENSICS_FIRST; ersetzt PATCH_NOW und PATCH_PLANNED. JSON: je Befund text plus
#                    details, mitigation_hits statt hits. OUTRE (eigene Hosts) mit Grenzen wie IP-Indikatoren.
#   17.4 2026-10-20  Fix: EOL_RELEASES wurde nie ausgewertet (EOL blieb 0); 12.1 und 13.0 erschienen gelb "Train nicht in
#                    der Regeldatei" statt rot End-of-Life. Jetzt REL gegen EOL_RELEASES geprueft. Fixture eol (12.1-65.25).
#   17.3 2026-10-20  Fix: Arbeitsverzeichnis $BASE_DIR/tmp (Vorgabe, konfigurierbar WORK_BASE, Rueckfall /var/tmp) statt /tmp (auf NetScaler liegt /tmp auf dem kleinen Root-
#                    Dateisystem; --compare entpackte das Snapshot-Set dorthin, "/: write failed, filesystem is full").
#                    Platzpruefung vor dem Entpacken, Meldung nennt den Grund. Betraf jede Version seit --compare (9.0).
#   17.2 2026-10-20  Terminal zeigt alles, was in den Report geht (bisher --full); --brief liefert die Kurzfassung ohne
#                    Detailzeilen. INFO-Zeilen (Custom geladen, inaktive Zeilen, Whitelist, Ziel-Build, Boot, Partitionen, AAA-Sessions,
#                    Simple ACLs) in jedem Modus im Terminal, nicht nur mit --no-out oder --full. Anonymisierung erweitert: Objektnamen aus ns.conf (vServer, Policies, Actions, Profile, Server, Service-
#                    gruppen, Zertifikate, Themes) und Theme-Verzeichnisse ausserhalb der Stock-Themes werden ersetzt; Lab-
#                    Lauf 20.10. zeigte Betreibernamen in Theme-Pfaden und Policy-Namen der Responder-Zeilen.
#   17.1 2026-10-20  Anonymisierter Report je Lauf (ns_quickcheck_<ersatzhost>_<zeit>_anon.txt/.json, Dateiname ohne Hostnamen) nach Zuordnungstabelle ns_quickcheck.anon.map
#                    (interne Adressen, Hostnamen, System-User, Auth-Server und Domains aus ns.conf; Angreifer-Werte,
#                    Hashes, Pfade bleiben); Option --anon <datei> fuer beliebige Logauszuege; custom= und
#                    custom_sha256 in RESULT/JSON; Quelle (Erstautor, Datum) beim Treffer auf Payload-Pfad.
#   17.0 2026-10-20  Fix: SAML-abhaengige CVE (z. B. CVE-2026-107406) setzte VULN9 nicht, weil die OPEN-Zeile die Bedingung
#                    ohne "conf:"-Praefix traegt; jetzt in der CVE-Schleife gesetzt (Bedingung enthaelt saml, Build
#                    ungefixt). Fix: IP-Indikatoren mit Grenzen, kein Teilstring-Treffer (1a.b.c.d5). IOC-Listen
#                    dedupliziert. Befunde aus dem Collector-Chat 20.10.
#   16.0 2026-10-19  Regeldatei Format 2: Indikatoren (ip, dom, hash, path) als Zeilen mit Herkunft (Quelle, Datum, Klasse,
#                    Fundstelle) im Abschnitt IOC; das Script baut ATTACKER_IP_RE, ATTACKER_DOM_RE, PAYLOAD_HASHES und
#                    PAYLOAD_PATHS beim Laden. Zeilen mit PRUEFEN oder ENTFERNEN in der Fundstelle sind inaktiv und
#                    werden gezaehlt. Format 1 wird weiter gelesen. Zusaetzlich wird ns_quickcheck.rules.custom
#                    (Betreiberdatei, gleicher Aufbau) additiv geladen, wenn sie neben der Regeldatei liegt. Anlass: Herkunft je Wert, siehe Changelog 2026-10-19.
#   15.1 2026-10-19  httpd.conf-mtime abseits der Boot-Zeit ist nur noch ROT, wenn der Inhalt einen Befund hat (Alias in
#                    Gateway-Pfade, PHP-Handler/-Flags). Sonst GELB mit Hinweis auf Installation/Upgrade (installns schreibt
#                    httpd.conf; Datei wird nicht bei jedem Boot neu erzeugt). Fehlalarm auf frischer 14.1-73.46 am 19.10.
#   15.0 2026-10-14  Fix: Ausgabefunktion bei Hash-Treffer (ok -> grn), seit 12.0, erst mit Stock-Hash auf 14.1-73.46 sichtbar.
#                    14.0 validiert auf 14.1-73.46 online und offline.
#   14.0 2026-10-14  SUSPECT_PROC_RE mit dreistufiger Parent-Bewertung (SUSPECT_PROC_PARENT_OK_RE = Info, cron = gelb,
#                    sonst rot) und Kindprozess-Pruefung (SUSPECT_PROC_CHILD_RE unter dem Monitor-Script = rot). Befund Lab
#                    14.1-73.46: Aufruf durch Daemon monuploadd, nicht Cron. 13.0 validiert auf 14.1-73.46 online und offline.
#   13.0 2026-10-14  Absturz der NetScaler-sh (SIGSEGV) in Block 5 behoben: Klammergruppe { if ...; } innerhalb einer
#                    Pipeline in $( ) bei der System-User-Pruefung (seit 10.0, nur offline auf Linux gelaufen).
#                    Ersatz: grep -vxF mit Default. Regel: keine Klammergruppe innerhalb einer Kommandosubstitution.
#                    Dieselbe Form im mktemp-Fallback (seit 1.0, nie ausgefuehrt) vorsorglich ersetzt.
#   12.0 2026-10-14  CISA-SIGMA-Stand (Regeldatei 2026-10-14): SUSPECT_PROC_RE prueft die Prozessliste mit Parent
#                    (cron = gelb mit Hinweis, sonst rot); DROPPER_PATH_RE zaehlt Requests je Quell-IP in httpaccess
#                    (gelb, rot bei Quell-IP mit Injection-Zeile); STOCK_HASH_FILES gibt SHA-256 von Systemdateien aus,
#                    STOCK_FILE_HASHES bewertet, wenn gefuellt. Unbekannte Variablen bleiben wie bisher ignoriert.
#   11.0 2026-10-13  --testlog <datei|verzeichnis>: prueft die Log-Muster der Regeldatei gegen Testlogs (docs/testlogs/)
#                    und vergleicht mit expected.txt (<datei>:<pruefung>:<mindestanzahl>, '*' = alle Pruefungen,
#                    Mindestanzahl 0 = darf nicht treffen). PASS/FAIL je Erwartung, Exit 0/1. Liest keine Appliance,
#                    keine Config, keine Whitelist. Pflichtschritt bei jeder Regelaenderung.
#   10.0 2026-10-08  Befunde aus der ersten Kundenabnahme: Hex-Blobs (Passwort-Hashes) im Diff ns.conf.0
#                    maskiert; CLI_USER aus der Config gilt automatisch als Service-User (keine gelbe Zeile,
#                    Anlage im ns.conf.0-Diff als Info statt Rot); Whitelist-Typ "mitigation:" ergaenzt
#                    MITIGATION_RULE_RE um betreibereigene Policy-Muster; --ki-bundle entfernt Zeilen mit
#                    CLI_USER; "Vergleich gegen Snapshot" immer auf dem Bildschirm; --compare cron waehlt
#                    das juengste Set mit status=complete. Regeldatei 2026-10-08e ohne Betreibernamen.
#   9.0  2026-10-08  Lizenz- und Urheberheader (Apache-2.0, ceterion AG, Jens Miltenberger), Disclaimer.
#                    Keine funktionale Aenderung gegenueber 8.0.
#   8.0  2026-10-08  Alias-Pruefung: Ziel in Anfuehrungszeichen (Stock: Alias /logon/ "/var/netscaler/logon/")
#                    wurde nicht als Stock-Wurzel erkannt; Anfuehrungszeichen werden vor dem Vergleich entfernt.
#   7.0  2026-10-08  httpd.conf-Alias-Pruefung nach Ziel statt nach Pfad: ein Alias in Gateway-Pfade ist
#                    nur dann ein Befund, wenn sein Ziel ausserhalb von STOCK_ALIAS_ROOTS (Regeldatei
#                    2026-10-08d) liegt. 14.1-Stock hat elf Aliase auf /var/ns_gui und /netscaler/portal.
#   6.0  2026-10-08  Fehlalarme aus dem ersten vollstaendigen Online-Lauf (Lab 14.1-73.41) beseitigt:
#                    httpd.conf-Pruefung nur noch Aliase in Gateway-Pfade und PHP-Flags in
#                    Directory-Bloecken fuer logon/vpn/epa (AddType php ist Stock); Interpreter-
#                    Listener auf Loopback gegen KNOWN_LISTENER_RE, bekannt = kein Befund, unbekannt
#                    auf Loopback = Gelb, auf anderen Adressen = Rot; Burst-Regel fuer Web-Dateien
#                    seit Boot (alle innerhalb 30 s = Rewrite, Info statt Gelb); --compare Listener
#                    beidseitig normalisiert; "Keine Mitigation-Policy" immer auf dem Bildschirm.
#                    Regeldatei 2026-10-08c: ADMIN_CMD_RE um sh_command= und nsprofmon_mgmt.pl,
#                    KNOWN_LISTENER_RE neu.
#   5.0  2026-10-08  Fix Segfault von /bin/sh in Block 3 (bestand in V4 fort): Klammergruppen
#                    "$( { ...; } | ... )" durch temporaere Dateien ersetzt (vier Stellen). Aelteres
#                    FreeBSD-sh auf NetScaler 14.1 stuerzt bei dieser Konstruktion ab.
#   4.0  2026-10-08  Fix Segfault von /bin/sh im Online-Lauf mit Reportdatei (Block 3): Ausgabe ohne
#                    Perl-Pipe je Zeile (Farben nur fuer den Bildschirm, Datei bekommt Klartext),
#                    Schleifen ueber temporaere Dateien statt Pipelines. Hit-Counter aus
#                    "show responder policy <name>" (stat kuerzt Namen und ignoriert den Parameter).
#                    --ki-bundle: Block 1 (Regeldatei) nicht mehr anonymisiert (zerstoerte CVE_TABLE),
#                    IPv6-Muster nur mit :: oder Hex-Buchstaben, Benutzer-Muster praeziser.
#                    Build-Zeile von Block 1 immer auf dem Bildschirm. Lab 14.1 vom 2026-10-08.
#   3.0  2026-10-08  CVE-Tabelle in der Regeldatei (CVE_TABLE: Bulletin|CVE|Train|Fix|Bedingung|Text) ersetzt
#                    die festen Slots und Bulletin-Namen in Block 1/2 (FIX_* bleiben als Fallback);
#                    Diff ns.conf gegen ns.conf.0 auf User, Policies, Auth, EPA; Hit-Counter-Deltas
#                    gegen den letzten Quickcheck-JSON; script_sha256 und rules_sha256 in RESULT/JSON;
#                    --ki-bundle erzeugt anonymisiertes Material fuer die KI-gestuetzte Regelpflege
#                    mit Selbstpruefung.
#   2.0  2026-10-07  Config-Datei mit Schichtung ueber ns_snapshot.conf; Report standardmaessig
#                    als Datei in REPORT_DIR plus JSON, Bildschirm nur Befunde (--full fuer alles);
#                    CLI-Ebene per nscli (Hit-Counter, Deny-List, Simple ACL, AAA-Sessions,
#                    Diff laufende/gespeicherte Config mit Snapshot-V5-Normalisierung);
#                    Zeitzonen-Abgleich bei der Quell-IP-Korrelation; Kunden-Whitelist;
#                    ausgehende Verbindungen gegen Payload-Hosts; --compare gegen Snapshot;
#                    HA-Peer- und save-ns-config-Hinweis im Verdict; Bootfile-Vergleich ohne .gz;
#                    rc=1 bei stat auf fehlende Objekte als Info; ALLOWED_SYSTEM_USERS.
#   1.0  2026-10-06  Erstfassung
# =============================================================================

PATH=/netscaler:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin; export PATH
LC_ALL=C; export LC_ALL
umask 077
VERSION="18.0"; RULES_MIN="2026-10-23"   # aeltere Regeldateien laufen, aber Pruefungen ohne ihre Variablen entfallen
SELF="$0"; case "$SELF" in /*) ;; *) SELF="$(pwd)/$SELF" ;; esac
SELFDIR=$(cd "$(dirname "$SELF")" 2>/dev/null && pwd || dirname "$SELF")
BASE_DIR=/var/nssnapshot
WORK_BASE=""            # Arbeitsverzeichnis fuer Zwischendateien und --compare; leer = $BASE_DIR/tmp (Rueckfall /var/tmp)

# --- Defaults ------------------------------------------------------------------
HOURS=72
REPORT_DIR="$BASE_DIR/quickcheck"
REPORT_KEEP_DAYS=30
LINE_MAX=400            # Zeichen je Logzeile in Terminal und Report; 0 = ungekuerzt
AAA_FAIL_IP=5           # Gateway-Anmeldefehler: ab so vielen Fehlversuchen von einer Adresse im Fenster Gelb
AAA_OK_WIN=5            # Minuten nach dem letzten Fehlversuch, in denen ein Erfolg desselben Kontos von derselben Adresse als "Nutzer" gilt
AAA_SLEEPER_DAYS=2      # Schlaefer: Fehlversuche an so vielen verschiedenen Tagen, mehrere Konten, unter Maschinen-Takt
AAA_BF_MIN=20           # Brute Force: ab so vielen Fehlversuchen auf ein einzelnes Konto im Fenster (von beliebig vielen Adressen)
AAA_RATE=10             # Fehlversuche je Minute, ab denen eine Adresse als Maschine gilt
AAA_FAIL_USERS=10       # ab so vielen verschiedenen Benutzernamen mit Fehlversuch von einer Adresse Gelb (Password Spraying)
CORE_BOOT_LEVEL=info    # leeres Core-Verzeichnis /var/core/<n> innerhalb 15 min nach Boot: info (Boot-Nachlauf) oder yellow (als Absturz-Ereignis)
LANG_QC=de              # Sprache von Report, Terminal und Adresslisten: de oder en (Katalog ns_quickcheck.msg.<sprache> neben dem Script)
TRUST_LEVEL=trust       # [TRUST] (Blau, ohne Verdict-Wirkung) oder yellow (als Gelb, mit Verdict-Wirkung)
FOOTER=1                # Fusszeile "Erstellt mit netscaler-quickcheck ..." im Report und in den anon-Fassungen; 0 = aus
PHP_ANOMALY_MIN=3       # PHP-Speicher-/Fatal-Muster im Management-Portal: ab so vielen Zeilen im Fenster wird gemeldet (CTX697263)
PROBE_LEVEL=yellow      # Webshell-Sondierungen: yellow (Vorgabe) oder info (nur Zaehlung, kein Einfluss auf das Verdict)
MGMT_NET_RE=""          # ERE fuer erlaubte Management-Adressen (z. B. "^10\.1\.|^192\.168\.10\."); leer = nur RFC 1918 gilt als intern
DETAIL_MAX=0            # Zeilen je Detailliste in Terminal und Report; 0 = alles (Vorgabe)
RULES_FILE=""
TESTLOG=""
WHITELIST_FILE=""; BLOCKED_FILE=""; TRUSTED_FILE=""; PIN_PATH=""; PIN_ALL=0; LANG_OPT=""
CLI_USER=""
CLI_SECRET_FILE="$BASE_DIR/ns_snapshot.secret"
CLI_TIMEOUT=20
ACCESS_LOG_MAX_MB=200
FROM=""; COMPARE=""; OUTFILE=""; NO_OUT=0; ANON_FILE=""; FULL=1; DO_CLI=1; CONF_FILE=""; KI_BUNDLE=0

# --- Config-Schichtung ---------------------------------------------------------
safe_file() { [ -f "$1" ] && perl -e '@s=stat($ARGV[0]) or exit 1; exit(($s[4]==0 && !($s[2] & 022)) ? 0 : 1)' "$1"; }
CFG_NOTE=""
SNAPCONF="$BASE_DIR/ns_snapshot.conf"
if safe_file "$SNAPCONF"; then
  _cu=$(sed -n 's/^CLI_USER=//p' "$SNAPCONF" | tail -1 | tr -d '"'"'"' ')
  _cs=$(sed -n 's/^CLI_SECRET_FILE=//p' "$SNAPCONF" | tail -1 | tr -d '"'"'"' ')
  _ct=$(sed -n 's/^CLI_TIMEOUT=//p' "$SNAPCONF" | tail -1 | tr -d '"'"'"' ')
  [ -n "$_cu" ] && { CLI_USER="$_cu"; CFG_NOTE="$(msg HDR_CFG_FROM_SNAPSHOT_CONF)"; }
  [ -n "$_cs" ] && CLI_SECRET_FILE="$_cs"
  [ -n "$_ct" ] && CLI_TIMEOUT="$_ct"
fi
# Erste Durchsicht der Argumente nur fuer --conf, damit die Datei vor den anderen Optionen geladen wird
_i=0; for _a in "$@"; do
  _i=$((_i + 1))
  case "$_a" in --conf) eval "CONF_FILE=\${$((_i + 1))}" ;; --conf=*) CONF_FILE="${_a#--conf=}" ;; esac
done
[ -n "$CONF_FILE" ] || CONF_FILE="$BASE_DIR/ns_quickcheck.conf"
if [ -f "$CONF_FILE" ]; then
  if safe_file "$CONF_FILE"; then
    _before="$CLI_USER"
    # shellcheck disable=SC1090
    . "$CONF_FILE"
    [ "$CLI_USER" != "$_before" ] && [ -n "$CLI_USER" ] && CFG_NOTE="$(msg HDR_CFG_FROM_QUICKCHECK_CONF)"
  else
    echo "$(msg ERR_CONF_IGNORED "$CONF_FILE")" >&2
  fi
fi

# --- Argumente (haben Vorrang) -------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --lang) [ $# -ge 2 ] && [ -n "$2" ] || { echo "ERROR: --lang braucht einen Wert: de oder en" >&2; exit 3; }; LANG_OPT="$2"; shift ;;
    --pin|--pin-all) [ $# -ge 2 ] && [ -n "$2" ] || { echo "$(msg ERR_PIN_NEEDS_PATH "$1" "$1")" >&2; exit 3; }; PIN_PATH="$2"; [ "$1" = "--pin-all" ] && PIN_ALL=1; shift ;;
    --hours|--from|--compare|--testlog|--rules|--whitelist|--blocked|--trusted|--conf|--out|--anon)
      [ $# -ge 2 ] && [ -n "$2" ] || { echo "$(msg ERR_OPT_NEEDS_VALUE "$1" "$1" "$1")" >&2; exit 3; }
      case "$1" in
        --hours) HOURS="$2" ;; --from) FROM="$2" ;; --compare) COMPARE="$2" ;; --testlog) TESTLOG="$2" ;;
        --rules) RULES_FILE="$2" ;; --whitelist) WHITELIST_FILE="$2" ;; --blocked) BLOCKED_FILE="$2" ;; --trusted) TRUSTED_FILE="$2" ;; --conf) ;; --out) OUTFILE="$2" ;; --anon) ANON_FILE="$2" ;;
      esac; shift ;;
    --hours=*)   HOURS="${1#--hours=}" ;;
    --from=*)    FROM="${1#--from=}" ;;
    --compare=*) COMPARE="${1#--compare=}" ;;
    --testlog=*) TESTLOG="${1#--testlog=}" ;;
    --rules=*)   RULES_FILE="${1#--rules=}" ;;
    --whitelist=*) WHITELIST_FILE="${1#--whitelist=}" ;;
    --blocked=*) BLOCKED_FILE="${1#--blocked=}" ;;
    --trusted=*) TRUSTED_FILE="${1#--trusted=}" ;;
    --conf=*)    ;;
    --out=*)     OUTFILE="${1#--out=}" ;;
    --no-out)    NO_OUT=1 ;;
    --anon=*)    ANON_FILE="${1#--anon=}" ;;
    --full)      FULL=1 ;;
    --brief)     FULL=0 ;;
    --no-cli)    DO_CLI=0 ;;
    --ki-bundle) KI_BUNDLE=1 ;;
    --version)   echo "ns_quickcheck $VERSION"; exit 0 ;;
    -h|--help)   awk 'NR>2 && /^# =====/{exit} NR>2' "$SELF"; exit 0 ;;
    *) echo "$(msg ERR_OPT_UNKNOWN "$1")" >&2; exit 3 ;;
  esac
  shift
done
case "$HOURS" in ''|*[!0-9]*) echo "$(msg ERR_HOURS_NOT_NUMBER)" >&2; exit 3 ;; esac

# --- Regeln und Whitelist ------------------------------------------------------
[ -n "$RULES_FILE" ] || { RULES_FILE="$SELFDIR/ns_quickcheck.rules"; [ -f "$RULES_FILE" ] || RULES_FILE="$BASE_DIR/ns_quickcheck.rules"; }
[ -r "$RULES_FILE" ] || { echo "$(msg ERR_RULES_UNREADABLE "$RULES_FILE")" >&2; exit 3; }
if perl -e '@s=stat($ARGV[0]) or exit 1; exit(($s[2] & 022) ? 1 : 0)' "$RULES_FILE"; then
  # shellcheck disable=SC1090
  . "$RULES_FILE"
else echo "$(msg ERR_RULES_WRITABLE "$RULES_FILE")" >&2; exit 3; fi
# Format 2: IOC-Zeilen nach der Marke "# ===== IOC" (typ TAB wert TAB quelle TAB datum TAB klasse TAB fundstelle).
# Die Zeilen stehen in einem Here-Document (: <<'IOC' ... IOC), daher fuehrt das Sourcen sie nicht aus.
IOC_INACTIVE=0
if [ "${RULES_FORMAT:-1}" = "2" ]; then
  ioc_re()   { awk -F'\t' -v t="$1" 'f && $1==t && $6 !~ /PRUEFEN|ENTFERNEN/ { if (seen[$1 SUBSEP $2]++) next; v=$2; gsub(/\./, "\\.", v); if (t == "ip") v = "(^|[^0-9.])" v "([^0-9.]|$)"; if (t == "dom") v = "(^|[^A-Za-z0-9-])" v "([^A-Za-z0-9.-]|$)"; s = s (s ? "|" : "") v } /^: <<'"'"'IOC'"'"'$/ { f=1 } /^IOC$/ { f=0 } END { printf "%s", s }' "$RULES_FILE"; }
  ioc_list() { awk -F'\t' -v t="$1" 'f && $1==t && $6 !~ /PRUEFEN|ENTFERNEN/ { if (seen[$1 SUBSEP $2]++) next; s = s (s ? " " : "") $2 } /^: <<'"'"'IOC'"'"'$/ { f=1 } /^IOC$/ { f=0 } END { printf "%s", s }' "$RULES_FILE"; }
  ATTACKER_IP_RE=$(ioc_re ip); ATTACKER_DOM_RE=$(ioc_re dom)
  PAYLOAD_HASHES=$(ioc_list hash); PAYLOAD_PATHS=$(ioc_list path)
  IOC_INACTIVE=$(awk -F'\t' 'f && !/^#/ && NF>=6 && $6 ~ /PRUEFEN|ENTFERNEN/ { n++ } /^: <<'"'"'IOC'"'"'$/ { f=1 } /^IOC$/ { f=0 } END { print n+0 }' "$RULES_FILE")
  # Quelle eines Indikators fuer die Befundzeile: " - Quelle: <quelle> <datum>" (Format 2, Regeldatei dann Custom)
ioc_src_raw() { for f in "$RULES_FILE" "${RULES_FILE}.custom"; do [ -r "$f" ] || continue
    r=$(awk -F'\t' -v t="$1" -v w="$2" 'f && $1==t && $2==w { printf "%s %s", $3, $4; exit } /^: <<'"'"'IOC'"'"'$/ { f=1 } /^IOC$/ { f=0 }' "$f"); [ -n "$r" ] && { printf '%s' "$r"; return; }; done; }
ioc_src() { _r=$(ioc_src_raw "$1" "$2"); [ -n "$_r" ] && msg TRACE_IOC_SOURCE_FRAG "${_r%% *}" "${_r#* }"; }
# Custom-Datei des Betreibers neben der Regeldatei: gleicher Aufbau, additiv, nicht verteilt
  CUSTOM_FILE="${RULES_FILE}.custom"; CUSTOM_N=0
  if [ -r "$CUSTOM_FILE" ]; then
    if perl -e '@s=stat($ARGV[0]) or exit 1; exit(($s[2] & 022) ? 1 : 0)' "$CUSTOM_FILE"; then
      ioc_re_c()   { awk -F'\t' -v t="$1" 'f && $1==t && $6 !~ /PRUEFEN|ENTFERNEN/ { if (seen[$1 SUBSEP $2]++) next; v=$2; gsub(/\./, "\\.", v); if (t == "ip") v = "(^|[^0-9.])" v "([^0-9.]|$)"; if (t == "dom") v = "(^|[^A-Za-z0-9-])" v "([^A-Za-z0-9.-]|$)"; s = s (s ? "|" : "") v } /^: <<'"'"'IOC'"'"'$/ { f=1 } /^IOC$/ { f=0 } END { printf "%s", s }' "$CUSTOM_FILE"; }
      ioc_list_c() { awk -F'\t' -v t="$1" 'f && $1==t && $6 !~ /PRUEFEN|ENTFERNEN/ { if (seen[$1 SUBSEP $2]++) next; s = s (s ? " " : "") $2 } /^: <<'"'"'IOC'"'"'$/ { f=1 } /^IOC$/ { f=0 } END { printf "%s", s }' "$CUSTOM_FILE"; }
      C=$(ioc_re_c ip);   [ -n "$C" ] && ATTACKER_IP_RE="${ATTACKER_IP_RE:+$ATTACKER_IP_RE|}$C"
      C=$(ioc_re_c dom);  [ -n "$C" ] && ATTACKER_DOM_RE="${ATTACKER_DOM_RE:+$ATTACKER_DOM_RE|}$C"
      C=$(ioc_list_c hash); [ -n "$C" ] && PAYLOAD_HASHES="$PAYLOAD_HASHES $C"
      C=$(ioc_list_c path); [ -n "$C" ] && PAYLOAD_PATHS="$PAYLOAD_PATHS $C"
      CUSTOM_VERSION=$(grep -m1 '^CUSTOM_VERSION=' "$CUSTOM_FILE" | sed 's/^CUSTOM_VERSION="\(.*\)"$/\1/')
      CUSTOM_N=$(awk -F'\t' 'f && !/^#/ && NF>=6 && $6 !~ /PRUEFEN|ENTFERNEN/ { n++ } /^: <<'"'"'IOC'"'"'$/ { f=1 } /^IOC$/ { f=0 } END { print n+0 }' "$CUSTOM_FILE")
      # CVE-Zeilen der Custom-Datei: identische Zeilen (CTX, CVE, Train, Fix, Bedingung) nur einmal; abweichende zusaetzlich mit Kennung [custom]
      CVE_CUSTOM_N=0; CVE_CONFLICT_N=0; CVE_CONFLICTS=""
      _cc=$(awk '/^: <<'"'"'CVE'"'"'$/ { f=1; next } /^CVE$/ { f=0 } f && !/^#/ && NF { print }' "$CUSTOM_FILE")
      if [ -n "$_cc" ]; then
        _rules_rows=$(echo "$CVE_TABLE" | grep -v '^[[:space:]]*$' | grep -v '^#')
        _add=$(echo "$_cc" | awk -F'::' -v R="$_rules_rows" -v mf="$(msg_raw HDR_CVE_CONFLICT_FIX_FRAG)" -v mc="$(msg_raw HDR_CVE_CONFLICT_COND_FRAG)" 'function m(t,a,b,c,d) { gsub(/%1/,a,t); gsub(/%2/,b,t); gsub(/%3/,c,t); gsub(/%4/,d,t); return t } BEGIN { n=split(R, a, "\n"); for (i=1;i<=n;i++) { split(a[i], f, "::"); same[f[1] "::" f[2] "::" f[3] "::" f[4] "::" f[5]]=1; key[f[1] "::" f[2] "::" f[3]]=f[4]; cond[f[1] "::" f[2] "::" f[3]]=f[5] } }
          { k5=$1 "::" $2 "::" $3 "::" $4 "::" $5; k3=$1 "::" $2 "::" $3; c++
            if (k5 in same) { d++; next }
            if (k3 in key) { conf++; if (key[k3] != $4) conflicts = conflicts m(mf, $2, $3, key[k3], $4) " "; else conflicts = conflicts m(mc, $2, $3, cond[k3], $5) " " }
            print $1 "::" $2 "::" $3 "::" $4 "::" $5 "::" $6 " [custom]" }
          END { printf "%d %d %d\n", c+0, d+0, conf+0 > "/dev/stderr"; print "CONFLICTS\t" conflicts > "/dev/stderr" }' 2>"$WORK/cvec.err")
        read -r CVE_CUSTOM_N _dup CVE_CONFLICT_N < "$WORK/cvec.err"
        CVE_CONFLICTS=$(awk -F'\t' '$1=="CONFLICTS" { print $2 }' "$WORK/cvec.err")
        [ -n "$_add" ] && CVE_TABLE=$(printf '%s\n%s\n' "$CVE_TABLE" "$_add")
      fi
    else echo "$(msg ERR_CUSTOM_WRITABLE "$CUSTOM_FILE")" >&2; fi
  fi
fi
for _v in RULES_VERSION TRIGGER_RE OBFUSC_RE CMD_NAMES LOGON_HINT_RE ADMIN_CMD_RE CVE_TABLE; do eval "_x=\${$_v:-}"; [ -n "$_x" ] || { echo "$(msg ERR_RULES_CORE_VAR_MISSING "$_v" "$RULES_FILE")" >&2; exit 3; }; done
: "${RULES_VERSION:=?}"; : "${SUSPECT_PROC_RE:=}"; : "${SUSPECT_PROC_PARENT_OK_RE:=}"; : "${SUSPECT_PROC_CHILD_RE:=}"; : "${DROPPER_PATH_RE:=}"; : "${STOCK_FILE_HASHES:=}"; : "${STOCK_HASH_FILES:=}"; : "${ALLOWED_SYSTEM_USERS:=}"; : "${ATTACKER_IP_RE:=}"; : "${ATTACKER_DOM_RE:=}"; : "${CVE_TABLE:=}"; : "${KNOWN_LISTENER_RE:=}"; : "${STOCK_ALIAS_ROOTS:=/netscaler/ /var/ns_gui/ /var/netscaler/ /var/vpn/ /var/python/ /var/nsinstall/}"
# Hashes von Script und Regeldatei fuer RESULT/JSON (FreeBSD sha256, sonst sha256sum)
sha256_of() { if command -v sha256 >/dev/null 2>&1; then sha256 -q "$1"; else sha256sum "$1" | cut -d' ' -f1; fi; }
SCRIPT_SHA=$(sha256_of "$SELF" 2>/dev/null); RULES_SHA=$(sha256_of "$RULES_FILE" 2>/dev/null)
CUSTOM_SHA=""; [ -r "${RULES_FILE}.custom" ] && CUSTOM_SHA=$(sha256_of "${RULES_FILE}.custom" 2>/dev/null)

# --- Testlog-Modus -------------------------------------------------------------
# Prueft die Log-Muster der Regeldatei gegen Testdateien. Nur Regex-Ebene plus die Injection-Pipeline
# aus Block 4 (ADMIN_CMD_RE-Ausschluss, LOGON_HINT_RE-Vorfilter). Keine Appliance, keine Whitelist.
if [ -n "$TESTLOG" ]; then
  : "${LOGON_HINT_RE:=}"; : "${TRIGGER_RE:=}"; : "${OBFUSC_RE:=}"; : "${CMD_NAMES:=}"; : "${LOGIN_PATH_RE:=}"
  : "${NSAAAD_CRASH_RE:=}"; : "${NSAAAD_CRASH_LEGACY_RE:=}"; : "${PITBOSS_RE:=}"; : "${KERNEL_EXIT_RE:=}"; : "${HTTPERR_CRASH_RE:=}"; : "${KERNEL_MEM_RE:=}"; : "${KERNEL_PANIC_RE:=}"; : "${DTLS_FAIL_RE:=}"; : "${PPE_CRASH_RE:=}"; : "${ADMIN_CMD_RE:=}"; : "${DROPPER_PATH_RE:=}"; : "${SUSPECT_PROC_RE:=}"; : "${HTTPERR_EXEC_RE:=}"; : "${HTTPERR_PROBE_RE:=}"; : "${AUTH_LOGIN_RE:=}"; : "${AUTH_FAIL_RE:=}"; : "${MGMT_PATH_RE:=}"; : "${AAA_FAIL_RE:=}"; : "${AAA_OK_RE:=}"; : "${HTTPERR_PHP_ANOMALY_RE:=}"
  CMDRE="[;|&\`]([[:space:]]|%20)*($CMD_NAMES)([[:space:]<>;|&\`\$]|%20|%3B|\\\$|$)|(%3B|%7C|%26)($CMD_NAMES)(%20|%24|%3B|%7C|$)"
  CHECKS="INJECTION TRIGGER_RE OBFUSC_RE CMD LOGIN_PATH_RE ATTACKER_IP_RE ATTACKER_DOM_RE NSAAAD_CRASH_RE NSAAAD_CRASH_LEGACY_RE PITBOSS_RE KERNEL_EXIT_RE HTTPERR_CRASH_RE KERNEL_MEM_RE KERNEL_PANIC_RE DTLS_FAIL_RE PPE_CRASH_RE DROPPER_PATH_RE SUSPECT_PROC_RE HTTPERR_EXEC_RE HTTPERR_PROBE_RE AUTH_LOGIN_RE AUTH_FAIL_RE MGMT_PATH_RE AAA_FAIL_RE AAA_OK_RE HTTPERR_PHP_ANOMALY_RE"
  tl_count() { # $1 datei $2 pruefung
    case "$2" in
      INJECTION) grep -avE "$ADMIN_CMD_RE" "$1" | grep -aiE "$LOGON_HINT_RE" | grep -acE "$TRIGGER_RE|$OBFUSC_RE|$CMDRE" ;;
      CMD)       grep -acE "$CMDRE" "$1" ;;
      ATTACKER_DOM_RE) eval "_re=\$$2"; if [ -n "$_re" ]; then grep -aciE "$_re" "$1"; else echo 0; fi ;;
      *)         eval "_re=\$$2"; if [ -n "$_re" ]; then grep -acE "$_re" "$1"; else echo 0; fi ;;
    esac
  }
  if [ -d "$TESTLOG" ]; then TLDIR="$TESTLOG"; TLFILES=$(ls "$TESTLOG"/*.log 2>/dev/null); else TLDIR=$(dirname "$TESTLOG"); TLFILES="$TESTLOG"; fi
  EXP="$TLDIR/expected.txt"
  [ -n "$TLFILES" ] || { echo "$(msg ERR_TESTLOG_NO_LOGS "$TESTLOG")" >&2; exit 3; }
  echo "$(msg TLOG_HEAD "$VERSION" "$RULES_VERSION" "$( [ -f "$EXP" ] && echo "$EXP" || echo $(msg TLOG_EXPECT_NONE) )")"
  NPASS=0; NFAIL=0
  for f in $TLFILES; do
    b=$(basename "$f"); echo "== $b"
    for c in $CHECKS; do
      n=$(tl_count "$f" "$c"); n=${n:-0}
      want=""
      if [ -f "$EXP" ]; then
        want=$(grep -E "^$b:($c|\*):" "$EXP" | grep -vE '^#' | tail -1 | cut -d: -f3)
      fi
      if [ -z "$want" ]; then printf '%s\n' "$(msg TLOG_ROW_NO_EXPECT "$(printf '%-16s' "$c")" "$(printf '%4s' "$n")")"; continue; fi
      if [ "$want" -eq 0 ]; then
        if [ "$n" -eq 0 ]; then st=PASS; NPASS=$((NPASS+1)); else st=FAIL; NFAIL=$((NFAIL+1)); fi
        printf '%s\n' "$(msg TLOG_ROW_EXPECT_ZERO "$(printf '%-16s' "$c")" "$(printf '%4s' "$n")" "$st")"
      else
        if [ "$n" -ge "$want" ]; then st=PASS; NPASS=$((NPASS+1)); else st=FAIL; NFAIL=$((NFAIL+1)); fi
        printf '%s\n' "$(msg TLOG_ROW_EXPECT_MIN "$(printf '%-16s' "$c")" "$(printf '%4s' "$n")" "$(printf '%-5s' "$want")" "$st")"
      fi
    done
    na=$(grep -acE "$ADMIN_CMD_RE" "$f"); printf '%s\n' "$(msg TLOG_ROW_ADMIN "$(printf '%-16s' ADMIN)" "$(printf '%4s' "$na")")"
  done
  # Erwartungen, deren Datei oder Pruefung es nicht gibt
  if [ -f "$EXP" ]; then
    grep -vE '^#|^[[:space:]]*$' "$EXP" | while IFS=: read -r ef ec ew; do
      [ -f "$TLDIR/$ef" ] || { echo "$(msg TLOG_FAIL_MISSING_FILE "$ef")"; }
      case " $CHECKS * " in *" $ec "*) ;; *) echo "$(msg TLOG_FAIL_UNKNOWN_CHECK "$ec")" ;; esac
    done | tee "$TLDIR/.exp_err.$$" ; NFAIL=$((NFAIL + $(grep -c . "$TLDIR/.exp_err.$$"))); rm -f "$TLDIR/.exp_err.$$"
  fi
  echo "$(msg TLOG_SUMMARY "$NPASS" "$NFAIL")"
  [ "$NFAIL" -eq 0 ] && exit 0 || exit 1
fi
[ -n "$WHITELIST_FILE" ] || WHITELIST_FILE="$SELFDIR/ns_quickcheck.whitelist"
WL_OK=0; [ -f "$WHITELIST_FILE" ] && { safe_file "$WHITELIST_FILE" && WL_OK=1 || echo "$(msg ERR_WHITELIST_IGNORED "$WHITELIST_FILE")" >&2; }
# wl <typ>: Regex-Alternation aller Whitelist-Regeln dieses Typs, leer wenn keine
wl() { [ "$WL_OK" -eq 1 ] || return 0; grep -E "^$1:" "$WHITELIST_FILE" 2>/dev/null | sed "s/^$1://" | grep -v '^[[:space:]]*$' | tr '\n' '|' | sed 's/|$//'; }
WL_USER=$(wl user); WL_LISTENER=$(wl listener); WL_PATH=$(wl path); WL_CRON=$(wl cron); WL_MITIG=$(wl mitigation)
# webfile-Regeln: optionaler Hash-Pin "webfile:<regex>@sha256=<hash>"; ohne Pin wie bisher, mit Pin nur bei gleichem Hash
WL_WEBFILE=$(wl webfile | tr '|' '\n' | sed 's/@sha256=[0-9a-f]*$//' | tr '\n' '|' | sed 's/|$//')
WL_WEBPIN="$WORK/wl_webpin.tsv"; : > "$WL_WEBPIN"
[ "$WL_OK" -eq 1 ] && grep -E '^webfile:.*@sha256=[0-9a-f][0-9a-f]*$' "$WHITELIST_FILE" 2>/dev/null | sed 's/^webfile://' | awk -F'@sha256=' 'length($2)==64 { printf "%s\t%s\n", $1, $2 }' > "$WL_WEBPIN"
# filter_wl <regex>: Zeilen entfernen, die auf die Whitelist passen (leerer Regex = nichts filtern)
filter_wl() { if [ -n "$1" ]; then grep -vE "$1"; else cat; fi; }

# --- Modus und Pfade -----------------------------------------------------------
if [ -n "$FROM" ]; then
  MODE=offline; ROOT="${FROM%/}"
  [ -d "$ROOT" ] || { echo "$(msg ERR_FROM_DIR_MISSING "$ROOT")" >&2; exit 3; }
  NSCONF="$ROOT/flash/nsconfig/ns.conf"; [ -f "$NSCONF" ] || NSCONF="$ROOT/nsconfig/ns.conf"
  STATE="$ROOT/state"; META="$ROOT/manifest/meta.tsv"; MANIFEST="$ROOT/manifest/files.tsv"
  DO_CLI=0
else
  [ -d /netscaler ] || { echo "$(msg ERR_NOT_NETSCALER)" >&2; exit 3; }
  [ "$(id -u)" -eq 0 ] || { echo "$(msg ERR_NOT_ROOT)" >&2; exit 3; }
  MODE=online; ROOT=""
  NSCONF=/nsconfig/ns.conf; STATE=""; META=""; MANIFEST=""
fi
[ -r "$NSCONF" ] || { echo "$(msg ERR_NSCONF_UNREADABLE "$NSCONF")" >&2; exit 3; }
LOGDIR="$ROOT/var/log"
ETC_HTTPD="$ROOT/etc/httpd.conf"; [ -f "$ETC_HTTPD" ] || ETC_HTTPD="$ROOT/flash/nsconfig/httpd.conf"
HOST=$(hostname 2>/dev/null | cut -d. -f1)
[ "$MODE" = offline ] && [ -f "$META" ] && HOST=$(awk -F'\t' '$1=="hostname"{print $2}' "$META")
[ -n "$HOST" ] || HOST=netscaler
TS=$(date +%Y%m%d_%H%M%S); NOW=$(date +%s)
# Arbeitsverzeichnis: /var/tmp (auf NetScaler das grosse Dateisystem), nicht /tmp auf dem kleinen Root-Dateisystem
WTMP="${WORK_BASE:-${TMPDIR:-}}"
if [ -z "$WTMP" ]; then
  if [ "$MODE" = online ] && [ -d "$BASE_DIR" ]; then WTMP="$BASE_DIR/tmp"; mkdir -p "$WTMP" 2>/dev/null; chmod 700 "$WTMP" 2>/dev/null; fi
  [ -n "$WTMP" ] && [ -w "$WTMP" ] || { [ -d /var/tmp ] && [ -w /var/tmp ] && WTMP=/var/tmp || WTMP=/tmp; }
fi
# Reste abgebrochener Laeufe im eigenen Arbeitsverzeichnis entfernen (aelter als ein Tag)
case "$WTMP" in "$BASE_DIR"/tmp) find "$WTMP" -maxdepth 1 -type d -name 'qc.*' -mtime +1 -exec rm -rf {} + 2>/dev/null ;; esac
WORK=$(mktemp -d "$WTMP/qc.XXXXXX" 2>/dev/null) || { WORK="$WTMP/qc.$$"; mkdir -p "$WORK"; }

# --- Nachrichtenkatalog (18.0): KEY<TAB>Text, Platzhalter %1..%9; de ist Pflicht, andere Sprachen fallen je Key auf de zurueck ---
MSG_LANG="${LANG_OPT:-${LANG_QC:-de}}"; case "$MSG_LANG" in de|en) ;; *) echo "ERROR: --lang: nur de oder en" >&2; exit 3 ;; esac
MSG_DE="$SELFDIR/ns_quickcheck.msg.de"; [ -f "$MSG_DE" ] || MSG_DE="$BASE_DIR/ns_quickcheck.msg.de"
MSG_FILE="$SELFDIR/ns_quickcheck.msg.$MSG_LANG"; [ -f "$MSG_FILE" ] || MSG_FILE="$BASE_DIR/ns_quickcheck.msg.$MSG_LANG"
[ -r "$MSG_DE" ] || { echo "ERROR: Nachrichtenkatalog nicht lesbar: $MSG_DE (gehoert neben das Script)" >&2; exit 3; }
msg_load() { awk -F'\t' '/^#/ || NF < 2 { next } { k=$1; t=$2; gsub(/'"'"'/, "'"'"'\\'"'"''"'"'", t); printf "MSG_%s='"'"'%s'"'"'\n", k, t }' "$1"; }
msg_load "$MSG_DE" > "$WORK/msg.sh"; MSG_MISSING=0
if [ "$MSG_LANG" != de ]; then
  if [ -r "$MSG_FILE" ]; then msg_load "$MSG_FILE" >> "$WORK/msg.sh"; grep -v '^#' "$MSG_DE" | cut -f1 | sort -u > "$WORK/msg_de.keys"; grep -v '^#' "$MSG_FILE" | cut -f1 | sort -u > "$WORK/msg_xx.keys"; MSG_MISSING=$(awk 'NR==FNR { k[$0]=1; next } !($0 in k)' "$WORK/msg_xx.keys" "$WORK/msg_de.keys" | grep -c .)
  else echo "WARN: Nachrichtenkatalog $MSG_FILE fehlt, Ausgabe auf Deutsch" >&2; MSG_LANG=de; fi
fi
. "$WORK/msg.sh"
MSG_SHA256=$(sha256 -q "$MSG_FILE" 2>/dev/null || sha256sum "$MSG_FILE" 2>/dev/null | cut -c1-64)
# msg KEY [wert1 ... wert9]: Text des Katalogs mit eingesetzten Platzhaltern; unbekannter Key wird als [KEY] gezeigt
msg() {
  _mk="$1"; shift; printf '%s' "$_mk" > "$WORK/msg.last" 2>/dev/null; eval "_mt=\"\${MSG_$_mk:-}\""; [ -n "$_mt" ] || { printf '%s' "[$_mk]"; return; }
  # Platzhalter ohne Muster in Anfuehrungszeichen (FreeBSD-sh-Parser): %n ist kein Glob-Zeichen, daher unquoted sicher
  _mi=1; for _mv in "$@"; do _mp="%$_mi"
    while :; do case "$_mt" in *$_mp*) _mt="${_mt%%$_mp*}$_mv${_mt#*$_mp}" ;; *) break ;; esac; done; _mi=$((_mi + 1)); done
  while :; do case "$_mt" in *%[1-9]*) _mr="${_mt#*%}"; _md=$(printf '%.1s' "$_mr"); _mp="%$_md"; _mt="${_mt%%$_mp*}${_mt#*$_mp}" ;; *) break ;; esac; done
  printf '%s' "$_mt"
}
# msg_raw KEY: Vorlage unveraendert (mit %n), fuer awk/perl, die selbst einsetzen
msg_raw() { eval "printf '%s' \"\${MSG_$1:-}\""; }
# Kennung als Spaltenfeld: auf 8 Zeichen aufgefuellt, ab 8 Zeichen ein Leerzeichen dahinter (entspricht der Ausgabe bis 17.44)
tagf() { _t=$(msg "$1"); _l=${#_t}; if [ "$_l" -ge 8 ]; then printf '  %s ' "$_t"; else printf '  %-8s' "$_t"; fi; }

free_kb() { df -k "$1" 2>/dev/null | awk 'NR==2 { print $4 }'; }
trap 'rm -rf "$WORK"' EXIT INT TERM HUP


# --- Anonymisierung -------------------------------------------------------------
# Zuordnungstabelle je Appliance neben der Regeldatei: <art> TAB <original> TAB <ersatz>; stabil ueber Laeufe, Rechte 600.
# Ersetzt werden interne Adressen (ns.conf: NSIP, SNIP, vServer, Server, HA-Peer, dazu jede RFC-1918-Adresse im Text),
# Hostnamen, System-User ausser nsroot, Auth-Server-Namen, DNS-Suffixe, E-Mail-Adressen. Angreifer-Werte aus der
# Regeldatei, Hashes, Pfade, Zeitstempel und Regelstaende bleiben. Schadensbegrenzung, kein Beweis: Stichprobe vor Weitergabe.
ANON_MAP="$(dirname "$RULES_FILE")/ns_quickcheck.anon.${HOST}.map"
ANON_RESERVED='^(OK|INFO|WARN|GELB|ROT|ORANGE|TRUST|ACTION|RESULT|HINWEIS|NOTE|RED|YELLOW|user|root|nsroot|admin|none|null|true|false|host|ip|mail|bis|ab|seit|neu|ja|nein|und|oder|von|aus|auf|mit|im|in|an|zu|der|die|das|den|dem|des|ein|eine|the|and|for|not|until|since|from|new|yes|no|of|to|log|conf|json|txt|tsv)$'
# dazu alle Kennungen beider Kataloge (TAG_*), damit kein Konto namens "yellow" die Markierung maskiert
cat "$MSG_DE" "$MSG_FILE" 2>/dev/null | awk -F'\t' '/^TAG_/ { t=$2; gsub(/\[|\]/, "", t); print t }' | sort -u > "$WORK/tags.txt"
_tags=$(tr '\n' '|' < "$WORK/tags.txt" | sed 's/|$//'); _rest=$(printf '%s' "$ANON_RESERVED" | sed 's/^\^(//')
[ -n "$_tags" ] && ANON_RESERVED="^(${_tags}|${_rest}"
anon_add() { # art original
  [ -n "$2" ] || return 0
  if [ "$1" = user ] || [ "$1" = mail ]; then
    [ "${#2}" -ge 3 ] || return 0                          # Konten unter 3 Zeichen (z. B. "-") nie maskieren: zu viele Treffer im Fliesstext
    echo "$2" | grep -qiE "$ANON_RESERVED" && return 0     # reservierte Woerter des Reports nie als Konto behandeln
  fi
  grep -qF "	$2	" "$ANON_MAP" 2>/dev/null && return 0
  n=$(grep -c "^$1	" "$ANON_MAP" 2>/dev/null); n=$((n+1))
  case "$1" in
    ip)   if [ "$n" -le 254 ]; then r="198.51.100.$n"; else r="203.0.113.$((n-254))"; fi ;;
    host) r="gw-$(printf '%02d' "$n")" ;;
    user) r="user$(printf '%02d' "$n")" ;;
    dom)  r="example$n.net" ;;
    mail) r="user$n@example.net" ;;
    obj)  r="obj$(printf '%03d' "$n")" ;;
    theme) r="theme$(printf '%02d' "$n")" ;;
  esac
  printf '%s\t%s\t%s\n' "$1" "$2" "$r" >> "$ANON_MAP"
}
anon_map_build() {
  [ -f "$ANON_MAP" ] || { : > "$ANON_MAP"; chmod 600 "$ANON_MAP" 2>/dev/null; }
  anon_add host "$HOST"; [ -n "$HAPEER" ] && anon_add ip "$HAPEER"
  # Host-Header-Werte aus Responder-/Logzeilen (Hostname: x, Host: x): die Adresse, unter der der Angreifer das Gateway ansprach; Betreiberdatum, kein Angreiferwert
  if [ -n "${INJ:-}" ]; then
    echo "$INJ" | grep -aoE '(Hostname|Host): *[A-Za-z0-9.-]+' | awk -F': *' '{print $2}' | sort -u | while IFS= read -r v; do
      echo "$v" | grep -qiE "${ATTACKER_IP_RE:-^\$}|${ATTACKER_DOM_RE:-^\$}" && continue
      echo "$HOSTS" | grep -qx "$v" && continue
      if echo "$v" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then anon_add ip "$v"; else anon_add dom "$v"; fi; done
  fi
  if [ -r "$NSCONF" ]; then
    for v in $(cg '^set ns hostName ' | awk '{print $4}'); do anon_add host "$v"; done
    for v in $(cg '^add ns ip6? ' | awk '{print $4}'); do anon_add ip "$v"; done
    for v in $(cg '^add (lb|cs|vpn|authentication|gslb|cr) vserver ' | awk '{print $5}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'); do anon_add ip "$v"; done
    for v in $(cg '^add server ' | awk '{print $4}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'); do anon_add ip "$v"; done
    for v in $(cg '^add HA node ' | awk '{print $5}'); do anon_add ip "$v"; done
    # bekannte Backdoor-Konten bleiben lesbar (sie sind Befund, kein Betreiberdatum)
    for v in $(cg '^add system user ' | awk '{print $4}' | grep -vE '^(nsroot|sec_monitor|gw_health)$'); do anon_add user "$v"; done
    for v in $(cg ' -serverName ' | sed 's/.*-serverName \([^ ]*\).*/\1/' | grep -v '^$'); do anon_add dom "$v"; done
    for v in $(cg '^add dns suffix ' | awk '{print $4}'); do anon_add dom "$v"; done
    # Objektnamen: add <modul> <typ> <name> ... (vServer, Policies, Actions, Profile, Server, Servicegroups, Zertifikate);
    # nur Namen ab 4 Zeichen, die nicht Stock-Bezeichner sind
    cg '^add (lb|cs|vpn|authentication|gslb|cr|responder|rewrite|appfw|ssl|dns|audit|system|cache|policy|appflow|ns) (vserver|policy|action|profile|server|servicegroup|service|certkey|label|expression|monitor|group|cmdPolicy|samlAction|samlIdPProfile|ldapAction|radiusAction|loginSchema|sessionAction|sessionPolicy|trafficAction|trafficPolicy|tacacsAction|certAction|OAuthAction|OAuthIDPProfile|portaltheme|variable|tcpParam) ' \
      | awk '{print $4}' | sed 's/^"//; s/"$//' | awk 'length($0) >= 4' | grep -vE '^(nsroot|Default|Greenbubble|Caxton|RfWebUI|X1|DEFAULT|NOPOLICY|ns_true|ns_false|HTTP|SSL|TCP)$' | sort -u \
      | while IFS= read -r v; do anon_add obj "$v"; done
    # FQDNs aus Server-Objekten, Monitoren und Auth-Aktionen; Zertifikats- und Schluesseldateien; DN-Komponenten
    for v in $(cg '^add server ' | awk '{print $4}' | grep -E '^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'); do anon_add dom "$v"; done
    for v in $(cg ' -(destIP|serverName|lbSite|hostname|hostName) ' | sed 's/.*-\(destIP\|serverName\|lbSite\|hostname\|hostName\) \([^ ]*\).*/\2/' | grep -E '^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'); do anon_add dom "$v"; done
    for v in $(cg '^add ssl certKey ' | grep -oE '(-cert|-key) "?[^" ]+' | awk '{print $2}' | tr -d '"' | grep -E '\.(pem|crt|cer|key|pfx|p12|der)$' | sort -u); do anon_add obj "$v"; done
    for v in $(cg '^add server ' | awk '{print $3}'); do anon_add obj "$v"; done
    for v in $(cg ' -serverIP ' | sed 's/.*-serverIP \([0-9.]*\).*/\1/' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'); do anon_add ip "$v"; done
    for v in $(cg ' -(bindDn|ldapBase|searchFilter|ssoNameAttribute) ' | grep -oiE 'dc=[A-Za-z0-9-]+' | sed 's/^[dD][cC]=//' | awk 'length($0) >= 3' | sort -u); do anon_add obj "$v"; done
    # Hostnamen aus URLs in Config-Werten (wihome, storefronturl, homePage, Redirects) und NT-/DNS-Domaenen
    for v in $(cg '' | grep -oiE 'https?://[A-Za-z0-9.-]+' | sed 's#^[hH][tT][tT][pP][sS]*://##' | grep -E '^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$' | sort -u); do anon_add dom "$v"; done
    for v in $(cg ' -(ntDomain|domain|dnsSuffix|emailDomain|defaultAuthenticationGroup) ' | grep -oE -- '-(ntDomain|domain|dnsSuffix|emailDomain|defaultAuthenticationGroup) "?[^" ]+' | awk '{print $2}' | tr -d '"' | awk 'length($0) >= 3' | sort -u); do anon_add dom "$v"; done
    for v in $(cg ' -(bindDn|ldapBase) ' | grep -oiE '(cn|ou)=[A-Za-z0-9 ._-]+' | sed 's/^[cC][nN]=//; s/^[oO][uU]=//' | awk 'length($0) >= 4' | sort -u); do anon_add obj "$v"; done
    # Theme-Verzeichnisse ausserhalb der Stock-Themes
    for v in $(ls "$ROOT/var/netscaler/logon/themes" 2>/dev/null | grep -vE '^(Default|Greenbubble|Caxton|RfWebUI|X1|default|greenbubble|caxton|rfwebui|x1)$'); do anon_add theme "$v"; done
  fi
}
anon_apply() { # infile outfile
  # dynamisch: RFC-1918-Adressen und E-Mail-Adressen im Text nachtragen, dann perl-Ersetzung, laengste Werte zuerst
  for v in $(grep -oE '\b(10\.[0-9]{1,3}|192\.168|172\.(1[6-9]|2[0-9]|3[01]))\.[0-9]{1,3}\.[0-9]{1,3}\b' "$1" 2>/dev/null | sort -u); do anon_add ip "$v"; done
  for v in $(grep -oE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' "$1" 2>/dev/null | sort -u); do anon_add mail "$v"; done
  _np=$(msg TRUST_NOTE_FRAG X | sed 's/^ *//; s/X.*$//')
  MAP="$ANON_MAP" SECRETS="$WORK/anon.secrets" ANONMODE="${3:-report}" RESERVED="$ANON_RESERVED" MSG_COMMENT_REMOVED="$(msg HDR_ANON_COMMENT_REMOVED)" MSG_NOTE_PREFIX="$_np" perl -e '
    open(my $m,"<",$ENV{MAP}) or exit 1; my @r; my $res=$ENV{RESERVED}; while (<$m>) { chomp; my ($k,$o,$n)=split /\t/; next unless defined $n;
      if ($k eq "user" || $k eq "mail") { next if length($o) < 3; next if $o =~ /$res/i }   # ungueltige Altlasten der Tabelle (17.33): nie ersetzen
      push @r,[$k,$o,$n] } close $m;
    @r = sort { length($b->[1]) <=> length($a->[1]) } @r; my $sec=0;
    my $keys = "password|ldapBindDnPassword|radKey|tacacsSecret|secret|sharedSecret|clientSecret|pskKey|community|tsigKey|passplain|encryptionKey|kek|ikeKey";
    while (my $l=<STDIN>) {
      # Geheimnisse ohne Tabelle maskieren: Wert hinter einem Secret-Parameter, Wert vor -encrypted, verschluesselte Bloecke
      $sec += ($l =~ s/(-(?:$keys)\s+)("[^"]*"|\S+)/$1***/gi);
      $sec += ($l =~ s/(add system user \S+\s+)("[^"]*"|\S+)/$1***/i);
      $sec += ($l =~ s/(add snmp community\s+)("[^"]*"|\S+)/$1***/i);
      $sec += ($l =~ s/\b[0-9a-f]{40,}\b(?=.*-encrypted)/***/gi);
      $l = $ENV{MSG_COMMENT_REMOVED} . "\n" if $ENV{ANONMODE} eq "file" && $l =~ /^#(?!NS[0-9])/;
      $l =~ s/ ?\Q$ENV{MSG_NOTE_PREFIX}\E[^\]]*\]//g;   # interne Bemerkung der Sperr- und Vertrauensliste nur im Original (Marker aus dem Katalog)
      for my $e (@r) { my ($k,$o,$n)=@$e; my $q=quotemeta($o);
        if ($k eq "ip") { $l =~ s/(?<![0-9.])$q(?![0-9.])/$n/g }
        elsif ($k eq "host") { $l =~ s/(?<![A-Za-z0-9.-])$q(?![A-Za-z0-9-])/$n/gi }   # Hostnamen auch in Dateinamen (ns_quickcheck_<host>_...) und vor Domain-Suffix
        else { $l =~ s/(?<![A-Za-z0-9._-])$q(?![A-Za-z0-9_-])/$n/gi } }
      # Nachlauf: der Hostname darf nirgends stehen bleiben, auch nicht innerhalb anderer Zeichenketten
      for my $e (@r) { my ($k,$o,$n)=@$e; next unless $k eq "host"; my $q=quotemeta($o); $l =~ s/$q/$n/gi }
      print $l }
    open(my $sf,">",$ENV{SECRETS}); print $sf $sec; close $sf' < "$1" > "$2" 2>/dev/null
  ANON_SECRETS=$(cat "$WORK/anon.secrets" 2>/dev/null)
  chmod 600 "$2" 2>/dev/null
}
# --- Reportdateien -------------------------------------------------------------
if [ "$NO_OUT" -eq 0 ]; then
  if [ -z "$OUTFILE" ]; then
    if [ "$MODE" = online ]; then mkdir -p "$REPORT_DIR" 2>/dev/null; chmod 700 "$REPORT_DIR" 2>/dev/null
      OUTFILE="$REPORT_DIR/ns_quickcheck_${HOST}_${TS}.txt"
    else OUTFILE="./ns_quickcheck_${HOST}_${TS}.txt"; fi
  fi
  : > "$OUTFILE" 2>/dev/null || { echo "$(msg ERR_REPORT_NOT_WRITABLE "$OUTFILE")" >&2; NO_OUT=1; }
fi
JSONFILE="${OUTFILE%.txt}.json"
# letzter Quickcheck-JSON dieses Hosts (fuer Hit-Counter-Deltas)
PREV_JSON=""; PREV_TS=""
if [ "$MODE" = online ] && [ -d "$REPORT_DIR" ]; then
  PREV_JSON=$(ls -t "$REPORT_DIR"/ns_quickcheck_"${HOST}"_*.json 2>/dev/null | head -1)
  [ -n "$PREV_JSON" ] && PREV_TS=$(basename "$PREV_JSON" .json | sed "s/^ns_quickcheck_${HOST}_//")
fi

# --- Ausgabe -------------------------------------------------------------------
if [ -t 1 ]; then R=$(printf '\033[31m'); G=$(printf '\033[32m'); Y=$(printf '\033[33m'); O=$(printf '\033[38;5;208m'); T=$(printf '\033[36m'); B=$(printf '\033[1m'); N=$(printf '\033[0m')
else R=""; G=""; Y=""; B=""; N=""; fi
# out <text> [screen] [farbe]: Klartext in die Datei (ohne Pipe, ohne Fork); Bildschirm bei --full,
# screen=1 oder --no-out, dort mit Farbe. Kein Perl je Zeile mehr: die Pipe in einer Funktion innerhalb
# verschachtelter Schleifen hat /bin/sh auf 14.1 zum Absturz gebracht.
out() {
  if [ "$NO_OUT" -eq 0 ]; then printf '%s\n' "$1" >> "$OUTFILE"; fi
  if [ "$FULL" -eq 1 ] || [ "${2:-0}" -eq 1 ] || [ "$NO_OUT" -eq 1 ]; then
    case "${3:-}" in
      R) printf '%s%s%s\n' "$R" "$1" "$N" ;;
      Y) printf '%s%s%s\n' "$Y" "$1" "$N" ;;
      O) printf '%s%s%s\n' "${O:-$Y}" "$1" "$N" ;;
      T) printf '%s%s%s\n' "${T:-}" "$1" "$N" ;;
      G) printf '%s%s%s\n' "$G" "$1" "$N" ;;
      B) printf '%s%s%s\n' "$B" "$1" "$N" ;;
      *) printf '%s\n' "$1" ;;
    esac
  fi
}
hdr()  { out "" 1; out "== $1 ==" 1 B; }
red()  { out "$(tagf TAG_RED)$1" 1 R; }
yel()  { out "$(tagf TAG_YELLOW)$1" 1 Y; }
org()  { out "$(tagf TAG_ORANGE)$1" 1 O; }
tru()  { out "$(tagf TAG_TRUST)$1" 1 T; }
grn()  { out "$(tagf TAG_OK)$1" "${2:-0}" G; }
inf()  { out "$(tagf TAG_INFO)$1" "${2:-0}"; }
# Detailzeilen (Logzeilen, Pfade): defanged, nicht druckbare Zeichen ersetzt, 200 Zeichen
show() {
  LM="${LINE_MAX:-400}" perl -ne 'chomp; s/[^\t\x20-\x7e]/./g; s/[;|&`\$<>]/_/g; s/http(s?):/hxxp$1:/gi; my $m=$ENV{LM}+0; print "          | ", ($m>0 ? substr($_,0,$m) : $_), "\n"' 2>/dev/null \
  | awk -v n="${DETAIL_MAX:-0}" -v m="$(msg_raw TRACE_DETAIL_MORE)" 'n==0 || NR<=n {print} END{if(n>0 && NR>n) { gsub(/%1/, NR-n, m); gsub(/%2/, n, m); print "          | " m }}' | while IFS= read -r l; do out "$l" "${2:-0}"; printf 'D\t%s\n' "${l#          | }" >> "$JFIND"; done
}
mtime_of() { perl -e '@s=stat($ARGV[0]); print $s[9] if @s' "$1" 2>/dev/null; }
fmtdate()  { perl -MPOSIX -e 'print strftime("%Y-%m-%d %H:%M", localtime($ARGV[0]))' "$1" 2>/dev/null; }
catlogs()  { for _f in "$@"; do [ -f "$_f" ] || continue; case "$_f" in *.gz) gzip -dc "$_f" 2>/dev/null ;; *) cat "$_f" 2>/dev/null ;; esac; done; }
# catns: Syslog-Familie (ns.log, nsvpn.log, messages, notice.log). nsprofmon_mgmt.pl-Zeilen (CPU-Momentaufnahmen mit den
# Kommandozeilen laufender Prozesse, darunter grep und perl des Quickcheck samt Suchmustern) werden abgezweigt, damit kein
# Check sich selbst findet; identische Zeilen aus mehreren Dateien (messages spiegelt ns.log) zaehlen einmal.
NSPROF_FILE="$WORK/nsprofmon.txt"; : > "$NSPROF_FILE"
catns() { catlogs "$@" | awk -v pf="$NSPROF_FILE" '/nsprofmon_mgmt\.pl/ { print >> pf; next } !seen[$0]++' ; }
# before_syslog <epoch> <sekunden>: Syslog-Zeilen aus STDIN, deren Kopfzeit in [epoch-sekunden, epoch] liegt; before_apache dito fuer Access-Log-Zeilen
before_syslog() { CE="$1" WIN="$2" perl -MTime::Local -ne 'my %M=(Jan=>0,Feb=>1,Mar=>2,Apr=>3,May=>4,Jun=>5,Jul=>6,Aug=>7,Sep=>8,Oct=>9,Nov=>10,Dec=>11); my $cy=(localtime)[5]+1900; if (/^([A-Z][a-z][a-z]) +(\d+) (\d\d):(\d\d):(\d\d)/) { my $e=timelocal($5,$4,$3,$2,$M{$1},$cy); print if $e >= $ENV{CE}-$ENV{WIN} && $e <= $ENV{CE} }'; }
before_apache() { CE="$1" WIN="$2" perl -MTime::Local -ne 'my %M=(Jan=>0,Feb=>1,Mar=>2,Apr=>3,May=>4,Jun=>5,Jul=>6,Aug=>7,Sep=>8,Oct=>9,Nov=>10,Dec=>11); if (m{\[(\d+)/([A-Z][a-z][a-z])/(\d\d\d\d):(\d\d):(\d\d):(\d\d)}) { my $e=timelocal($6,$5,$4,$1,$M{$2},$3); print if $e >= $ENV{CE}-$ENV{WIN} && $e <= $ENV{CE} }'; }
# die zwei juengsten Dateien eines Musters, unabhaengig vom Alter (fuer das KI-Bundle)
logs_in_window_all() { ls -t "$LOGDIR"/$1 2>/dev/null | head -2; }
cg()  { grep -iE -e "$1" "$NSCONF" 2>/dev/null; }
if [ -n "$ANON_FILE" ]; then
  [ -r "$ANON_FILE" ] || { echo "$(msg ERR_ANON_FILE_UNREADABLE "$ANON_FILE")" >&2; exit 3; }
  anon_map_build; anon_apply "$ANON_FILE" /dev/stdout file
  echo "$(msg ERR_ANON_SUMMARY "$(wc -l < "$ANON_MAP" | tr -d ' ')" "${ANON_SECRETS:-0}")" >&2; exit 0
fi

cgc() { grep -icE -e "$1" "$NSCONF" 2>/dev/null; }
state_or() { _n="$1"; shift; if [ "$MODE" = offline ]; then cat "$STATE/$_n.txt" 2>/dev/null; else "$@" 2>/dev/null; fi; }
# JSON-Befundlisten (eine Zeile je Befund, defanged, ohne Farben)
JRED="$WORK/red.txt"; JYEL="$WORK/yel.txt"; JFIND="$WORK/findings.tsv"; JIPS="$WORK/ips.tsv"; : > "$JRED"; : > "$JYEL"; : > "$JFIND"; : > "$JIPS"
# ip_note <kategorie> <adresse> [anzahl] [quelle]: beobachtete fremde Adresse fuer die Adressliste; eigene und private Adressen nicht
ip_note() { case "$2" in 10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|127.*|0.*|169.254.*) return ;; esac
  _ti=$(trusted_info "$2" 2>/dev/null)
  if [ -n "$_ti" ]; then printf 'trusted_%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "${3:-1}" "${4:-} (trusted$( [ -n "${_ti#*|}" ] && echo "$(msg TRUST_UNTIL_FRAG "${_ti#*|}"): ${_ti%%|*})")" "$(blocked_info "$2")" >> "$JIPS"; trust_event "$2" "$1: ${3:-1} (${4:-})"
  else printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "${3:-1}" "${4:-}" "$(blocked_info "$2")" >> "$JIPS"; fi; }
# Sperrliste des Betreibers: ns_quickcheck.blocked_ips neben dem Script oder --blocked <pfad> (adresse_oder_netz TAB wo TAB seit TAB ticket TAB kommentar); dazu ACLs der Appliance
[ -n "$BLOCKED_FILE" ] || BLOCKED_FILE="$SELFDIR/ns_quickcheck.blocked_ips"; BLOCKED_TAB="$WORK/blocked.tsv"; : > "$BLOCKED_TAB"
if [ -r "$BLOCKED_FILE" ]; then
  if perl -e '@s=stat($ARGV[0]) or exit 1; exit(($s[2] & 022) ? 1 : 0)' "$BLOCKED_FILE"; then
    # Format: adresse_oder_netz ; seit ; Bemerkung  (Tab als Trenner weiter erlaubt); Tabelle intern: adresse TAB bemerkung TAB seit TAB leer
    awk 'BEGIN { bad=""; nodate=0 } /^#/ || /^[[:space:]]*$/ { next }
      { line=$0; if (index(line, ";")) { gsub(/\t/, " ", line); n=split(line, f, ";") } else n=split(line, f, "\t")
        for (i=1;i<=n;i++) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", f[i]) }
        a=f[1]; sub(/\/.*/, "", a); if (n < 1 || a !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) { bad = bad NR " "; next }
        seit=f[2]; bem=f[3]; for (i=4;i<=n;i++) bem = bem ";" f[i]
        if (seit !~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/) { if (seit != "" && seit !~ /^[0-9-]*$/) { bem = seit (bem != "" ? ", " bem : "") } nodate++; seit="" }
        print f[1] "\t" bem "\t" seit "\t" > "/dev/stdout" }
      END { printf "%s\t%d\n", bad, nodate > "/dev/stderr" }' "$BLOCKED_FILE" >> "$BLOCKED_TAB" 2>"$WORK/blocked.info"
    BLOCKED_BAD=$(cut -f1 "$WORK/blocked.info" | sed 's/ $//'); BLOCKED_NODATE=$(cut -f2 "$WORK/blocked.info")
    BLOCKED_PRESENT=1
  else echo "$(msg ERR_BLOCKED_WRITABLE "$BLOCKED_FILE")" >&2; fi
fi
# ACLs der Appliance (DENY mit srcIP) gelten als Sperre "netscaler" ohne Datum: markiert, aber nicht abgedeckt
cg '^add ns (simpleacl|acl6?|acl) ' | grep -i ' DENY' | grep -oE -- '-srcIP(6)? (= )?[0-9.]+(-[0-9.]+)?' | awk '{ v=$NF; sub(/-.*/, "", v); if (v ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print v "\tnetscaler\t\t" }' | sort -u >> "$BLOCKED_TAB"
BLOCKED_N=$(grep -c . "$BLOCKED_TAB"); BLOCKED_PRESENT=${BLOCKED_PRESENT:-0}
# Vertrauensliste des Betreibers: ns_quickcheck.trusted_ips neben dem Script oder --trusted <pfad>; Format adresse_oder_netz ; bis ; Bemerkung
[ -n "$TRUSTED_FILE" ] || TRUSTED_FILE="$SELFDIR/ns_quickcheck.trusted_ips"; TRUSTED_TAB="$WORK/trusted.tsv"; : > "$TRUSTED_TAB"; TRUST_EVENTS="$WORK/trust_events.tsv"; : > "$TRUST_EVENTS"
TRUSTED_N=0; TRUSTED_EXPIRED=0; TRUSTED_BAD=""; TRUSTED_PRESENT=0; : > "$WORK/trusted_expired.tsv"
if [ -r "$TRUSTED_FILE" ]; then
  if perl -e '@s=stat($ARGV[0]) or exit 1; exit(($s[2] & 022) ? 1 : 0)' "$TRUSTED_FILE"; then
    TRUSTED_PRESENT=1; _today=$(date +%Y-%m-%d)
    awk -v today="$_today" 'BEGIN { bad=""; expd=0 } /^#/ || /^[[:space:]]*$/ { next }
      { line=$0; if (index(line, ";")) { gsub(/\t/, " ", line); n=split(line, f, ";") } else n=split(line, f, "\t")
        for (i=1;i<=n;i++) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", f[i]) }
        a=f[1]; sub(/\/.*/, "", a); if (n < 1 || a !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) { bad = bad NR " "; next }
        bis=f[2]; bem=f[3]; for (i=4;i<=n;i++) bem = bem ";" f[i]
        if (bis !~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/) { if (bis != "" && bis !~ /^[0-9-]*$/) { bem = bis (bem != "" ? ", " bem : "") } bis="" }
        if (bis != "" && bis < today) { expd++; print f[1] "\t" bem "\t" bis > expfile; next }
        print f[1] "\t" bem "\t" bis > "/dev/stdout" }
      END { printf "%s\t%d\n", bad, expd > "/dev/stderr" }' expfile="$WORK/trusted_expired.tsv" "$TRUSTED_FILE" >> "$TRUSTED_TAB" 2>"$WORK/trusted.info"
    TRUSTED_BAD=$(cut -f1 "$WORK/trusted.info" | sed 's/ $//'); TRUSTED_EXPIRED=$(cut -f2 "$WORK/trusted.info")
  else echo "$(msg ERR_TRUSTED_WRITABLE "$TRUSTED_FILE")" >&2; fi
fi
TRUSTED_N=$(grep -c . "$TRUSTED_TAB")
# trusted_info <ip>: "bemerkung|bis" oder leer; Netze als a.b.c.d/n
trusted_info() {
  [ -s "$TRUSTED_TAB" ] || return 0
  awk -F'\t' -v ip="$1" 'function toint(a, p) { split(a, p, "."); return ((p[1]*256+p[2])*256+p[3])*256+p[4] }
    { n=$1; bits=32; if (index(n,"/")) { bits=substr(n,index(n,"/")+1); n=substr(n,1,index(n,"/")-1) }
      if (n !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) next
      if (int(toint(ip)/2^(32-bits)) == int(toint(n)/2^(32-bits))) { printf "%s|%s", $2, $3; exit } }' "$TRUSTED_TAB"
}
is_trusted_ip() { [ -n "$(trusted_info "$1")" ]; }
# trusted_expired_info <ip>: Ablaufdatum, wenn die Adresse in trusted_ips steht, der Eintrag aber abgelaufen ist (Hinweis, keine Bewertung)
trusted_expired_info() {
  [ -s "$WORK/trusted_expired.tsv" ] || return 0
  awk -F'\t' -v ip="$1" 'function toint(a, p) { split(a, p, "."); return ((p[1]*256+p[2])*256+p[3])*256+p[4] }
    { n=$1; bits=32; if (index(n,"/")) { bits=substr(n,index(n,"/")+1); n=substr(n,1,index(n,"/")-1) }
      if (n !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) next
      if (int(toint(ip)/2^(32-bits)) == int(toint(n)/2^(32-bits))) { printf "%s", $3; exit } }' "$WORK/trusted_expired.tsv"
}
expired_tag() { _te=$(trusted_expired_info "$1"); [ -n "$_te" ] && msg TRUST_EXPIRED_TAG_FRAG "$_te"; }
# trusted_tag <ip>: Zusatz fuer Wirkungs-Befunde (Rot bleibt Rot); [Bemerkung: ...] entfernt die Anonymisierung
trusted_tag() { _ti=$(trusted_info "$1"); [ -n "$_ti" ] || return 0; _tb=$(echo "$_ti" | cut -d'|' -f2); _tm=$(echo "$_ti" | cut -d'|' -f1); msg TRUST_TAG_FRAG "$( if [ -n "$_tb" ]; then msg TRUST_UNTIL_FRAG "$_tb"; else msg TRUST_UNLIMITED_FRAG; fi )" "$( [ -n "$_tm" ] && msg TRUST_NOTE_FRAG "$_tm" )"; }
# trust_event <ip> <text>: was eine vertraute Adresse im Fenster getan hat, fuer den [TRUST]-Block
trust_event() { printf '%s\t%s\n' "$1" "$2" >> "$TRUST_EVENTS"; }
# blocked_info <ip>: "wo|seit|ticket" oder leer; Netze als a.b.c.d/n
blocked_info() {
  [ -s "$BLOCKED_TAB" ] || return 0
  awk -F'\t' -v ip="$1" 'function toint(a, p) { split(a, p, "."); return ((p[1]*256+p[2])*256+p[3])*256+p[4] }
    { n=$1; bits=32; if (index(n,"/")) { bits=substr(n,index(n,"/")+1); n=substr(n,1,index(n,"/")-1) }
      if (n !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) next
      mask = (bits==0) ? 0 : int(2^32 - 2^(32-bits)); if (int(toint(ip)/2^(32-bits)) == int(toint(n)/2^(32-bits))) { printf "%s|%s|%s", $2, $3, $4; exit } }' "$BLOCKED_TAB"
}
# blocked_covers <ip> <datum YYYY-MM-DD der Beobachtung>: 0 = gesperrt und Beobachtung vor dem Sperrdatum (abgedeckt), 1 sonst
blocked_covers() { _bi=$(blocked_info "$1"); [ -n "$_bi" ] || return 1; _since=$(echo "$_bi" | cut -d'|' -f2)
  case "$_since" in [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) [ "$(echo "$2" | tr -d -)" -lt "$(echo "$_since" | tr -d -)" ] && return 0 ;; esac; return 1; }
# Datum einer Syslog-Zeile ("Oct 19 ...") oder Access-Log-Zeile ("[19/Oct/2026:...]") als YYYY-MM-DD; Syslog ohne Jahr: aktuelles Jahr, Monat in der Zukunft = Vorjahr
log_date() { printf '%s\n' "$1" | perl -e 'my %m=(Jan=>1,Feb=>2,Mar=>3,Apr=>4,May=>5,Jun=>6,Jul=>7,Aug=>8,Sep=>9,Oct=>10,Nov=>11,Dec=>12);
  my @t=localtime; my ($cy,$cm)=($t[5]+1900,$t[4]+1); my $l=<STDIN>; $l="" unless defined $l;
  if ($l =~ /\[(\d\d?)\/([A-Z][a-z][a-z])\/(\d\d\d\d)/ && $m{$2}) { printf "%04d-%02d-%02d\n", $3, $m{$2}, $1; exit }
  if ($l =~ /^([A-Z][a-z][a-z]) +(\d\d?) / && $m{$1}) { my $y=$cy; $y-- if $m{$1} > $cm; printf "%04d-%02d-%02d\n", $y, $m{$1}, $2; exit }
  if ($l =~ /^\[[A-Z][a-z][a-z] ([A-Z][a-z][a-z]) +(\d\d?) [\d:.]+ (\d\d\d\d)\]/ && $m{$1}) { printf "%04d-%02d-%02d\n", $3, $m{$1}, $2; exit }
  print "\n"'; }
blocked_tag() { _bi=$(blocked_info "$1"); [ -n "$_bi" ] || { expired_tag "$1"; return 0; }; _w=$(echo "$_bi" | cut -d'|' -f1); _s=$(echo "$_bi" | cut -d'|' -f2)
  _wn=$( [ -n "$_w" ] && msg TRUST_NOTE_FRAG "$_w" ); if [ -n "$_s" ]; then msg TRACE_BLOCKED_TAG_FRAG "$_s" "$_wn"; else msg TRACE_BLOCKED_TAG_NODATE_FRAG "$_wn"; fi; expired_tag "$1"; }
RED_COUNT=0; YEL_COUNT=0; ORG_COUNT=0; BLOCKED_SEEN=0
COMPROMISE=0; VULN=0; VULN9=0; VULN63=0; VULN96=0; NCRASH=0; EOL=0; ISN_OPEN=0; TRACES=0; MITIG_OK=0; SAML=0; SAVE_MISSING=0; UNSAVED=0
flag_red() { red "$1"; RED_COUNT=$((RED_COUNT + 1)); printf '%s\n' "$1" >> "$JRED"; printf 'R\t%s\n' "$1" >> "$JFIND"; }
flag_yel() { yel "$1"; YEL_COUNT=$((YEL_COUNT + 1)); printf '%s\n' "$1" >> "$JYEL"; printf 'Y\t%s\n' "$1" >> "$JFIND"; }
flag_org() { org "$1"; ORG_COUNT=$((ORG_COUNT + 1)); printf 'O\t%s\n' "$1" >> "$JFIND"; }
TRUST_COUNT=0
flag_tru() { if [ "${TRUST_LEVEL:-trust}" = yellow ]; then flag_yel "$1"; else tru "$1"; printf 'T\t%s\n' "$1" >> "$JFIND"; fi; TRUST_COUNT=$((TRUST_COUNT + 1)); }

# --- CLI-Ebene (wie ns_snapshot V5) --------------------------------------------
CLI_MODE=none; CLI_REASON=""; CLI_PW=""
detect_cli() {
  [ "$MODE" = online ] || { CLI_REASON="offline"; return; }
  [ "$DO_CLI" -eq 1 ] || { CLI_REASON="$(msg HDR_CLI_REASON_NO_CLI)"; return; }
  if [ -x /netscaler/cli_script.sh ] && /netscaler/cli_script.sh "show ns version" 2>/dev/null | grep -qi 'NetScaler'; then CLI_MODE=script; return; fi
  [ -n "$CLI_USER" ] || { CLI_REASON="$(msg HDR_CLI_REASON_NO_USER)"; return; }
  [ -x /netscaler/nscli ] || { CLI_REASON="$(msg HDR_CLI_REASON_NO_NSCLI)"; return; }
  [ -f "$CLI_SECRET_FILE" ] || { CLI_REASON="$(msg HDR_CLI_REASON_NO_SECRET)"; return; }
  perl -e '@s=stat($ARGV[0]) or exit 1; exit(($s[4]==0 && !($s[2] & 077)) ? 0 : 1)' "$CLI_SECRET_FILE" || { CLI_REASON="$(msg HDR_CLI_REASON_SECRET_PERMS)"; return; }
  CLI_PW=$(head -n 1 "$CLI_SECRET_FILE" | tr -d '\r\n'); [ -n "$CLI_PW" ] || { CLI_REASON="$(msg HDR_CLI_REASON_SECRET_EMPTY)"; return; }
  CLI_MODE=nscli
}
# cli <befehl>: Ausgabe auf stdout, mit Timeout; rc 0/1 vom Befehl, 124 bei Timeout
cli() {
  _o="$WORK/cli.out"; _e="$WORK/cli.err"
  case "$CLI_MODE" in
    script) /netscaler/cli_script.sh "$1" > "$_o" 2> "$_e" & ;;
    nscli)  /netscaler/nscli -s -U "%%:$CLI_USER:$CLI_PW" "$1" > "$_o" 2> "$_e" & ;;
    *) return 1 ;;
  esac
  _pid=$!; _w=0
  while kill -0 "$_pid" 2>/dev/null; do
    [ "$_w" -ge "$CLI_TIMEOUT" ] && { kill "$_pid" 2>/dev/null; sleep 1; kill -9 "$_pid" 2>/dev/null; cat "$_o"; return 124; }
    sleep 1; _w=$((_w + 1))
  done
  wait "$_pid" 2>/dev/null; _rc=$?; cat "$_o"; return $_rc
}
# cli_stat_info <befehl> <text>: rc=1 mit "No such"/"does not exist" ist Info, keine Stoerung
cli_missing() { grep -qiE 'no such|does not exist|not found|not configured|ERROR: Resource' "$WORK/cli.out" 2>/dev/null; }
detect_cli

# --- --ki-bundle: anonymisiertes Material fuer die KI-gestuetzte Regelpflege ---
if [ "$KI_BUNDLE" -eq 1 ]; then
  BDIR="${REPORT_DIR}"; [ "$MODE" = offline ] && BDIR="."
  mkdir -p "$BDIR" 2>/dev/null; chmod 700 "$BDIR" 2>/dev/null
  BFILE="$BDIR/ki_bundle_${HOST}_${TS}.txt"; BTMP="$WORK/bundle.txt"
  if [ "$MODE" = online ]; then FQDN=$(hostname 2>/dev/null); else FQDN=$(awk -F'\t' '$1=="hostname_full"{print $2}' "$META" 2>/dev/null); fi
  SHORT="$HOST"; [ "$FQDN" = "$SHORT" ] && FQDN=""
  [ -n "$SHORT" ] || { echo "$(msg ERR_KIB_NO_HOSTNAME)" >&2; exit 3; }
  HAIP=$(cg '^add HA node ' | awk '{print $5}' | tr '\n' '|' | sed 's/|$//')
  # Anonymisierung: Benutzernamen, IPv4/IPv6, Host, Session-IDs, Zertifikatsnamen
  # Anonymisierung nur fuer Logzeilen (Block 2). IPv6 nur, wenn :: oder ein Hex-Buchstabe enthalten ist,
  # damit Zeitstempel wie 2026:06:59:53 nicht ersetzt werden.
  anon() {
    SHORT="$SHORT" FQDN="$FQDN" perl -pe '
      s/username: <[^>]*>/username: <USER>/g;
      s/\b(ADM_User|User_name|user_name|Username|User)(=|:\s*)([^\s,"]+)/$1$2USER/g;
      s/\b(User)(\s+)(\S+)(?=\s+-)/$1$2USER/g;
      s/\b(\d{1,3}\.){3}\d{1,3}\b/IP.IP.IP.IP/g;
      s/(?<![\w:])((?:[0-9a-fA-F]{1,4}:){1,7}:?(?:[0-9a-fA-F]{1,4})?)(?![\w:])/ ($1 =~ m{::} or $1 =~ m{[a-fA-F]}) ? "IP6" : $1 /ge;
      s/SessionId[=: ]+[^ ,]+/SessionId=SESSION/g; s/Vserver \S+/Vserver VSERVER/g;
      if (length $ENV{FQDN}) { s/\Q$ENV{FQDN}\E/HOST/g } s/\Q$ENV{SHORT}\E/HOST/g;
    '
  }
  # Zeilen, die NICHT in das Bundle duerfen: Angriffsmuster, kurze Passwoerter (Testkonten), Admin-Logins mit Fehlern
  clean_only() { grep -avE "$TRIGGER_RE|$OBFUSC_RE|[;|&\`]([[:space:]]|%20)*($CMD_NAMES)|pwdlen [0-7],|Failure|failed|denied"; }
  {
    echo "$(msg KIB_BLOCK1_HEAD)"
    echo "$(msg KIB_BLOCK1_NOTE)"
    if [ -n "$CLI_USER" ]; then grep -vE '^ALLOWED_SYSTEM_USERS=' "$RULES_FILE" | grep -vF -- "$CLI_USER"; else grep -vE '^ALLOWED_SYSTEM_USERS=' "$RULES_FILE"; fi
    echo; echo "$(msg KIB_BLOCK2_HEAD)"
    echo "$(msg KIB_B2_NSLOG_LOGONS)"
    catlogs $(logs_in_window_all 'ns.log*') | grep -a 'AAA LOGIN REQ' | clean_only | tail -3 | anon
    echo "$(msg KIB_B2_HTTPACCESS_LOGONS)"
    catlogs $(logs_in_window_all 'httpaccess*') | grep -aE "\"(POST|GET) [^\"]*($LOGIN_PATH_RE)" | grep -aE '" (200|302) ' | clean_only | tail -3 | anon
    echo "$(msg KIB_B2_NSLOG_ADMIN_CMD)"
    catlogs $(logs_in_window_all 'ns.log*') | grep -a 'CMD_EXECUTED' | grep -a 'Status "Success"' | tail -1 | anon
    echo "$(msg KIB_B2_NSLOG_NSAAAD_OK)"
    catlogs $(logs_in_window_all 'ns.log*') | grep -a 'nsaaad' | grep -avE 'exited|signal|LOGIN REQ' | clean_only | tail -1 | anon
    echo; echo "$(msg KIB_BLOCK3_HEAD)"
    echo "$(msg KIB_B3_BULLETIN_ID)"
    echo "$(msg KIB_B3_BULLETIN_TEXT)"
  } > "$BTMP" 2>/dev/null
  # Selbstpruefung auf Block 2 (Logzeilen): keine IP in Ziffernform, kein Hostname, kein Benutzername der Logs.
  # Block 1 (Regeldatei) enthaelt Angreifer-IPs und Kommandonamen absichtlich und wird nicht geprueft.
  sed -n '/^### BLOCK 2/,/^### BLOCK 3/p' "$BTMP" > "$WORK/b2.txt"
  LEAK=""
  grep -aqE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$WORK/b2.txt" && LEAK="$(msg KIB_LEAK_IP)"
  [ -n "$SHORT" ] && grep -aqF "$SHORT" "$WORK/b2.txt" && LEAK="${LEAK:+$LEAK, }$(msg KIB_LEAK_HOSTNAME)"
  [ -n "$HAIP" ] && grep -aqE "$HAIP" "$WORK/b2.txt" && LEAK="${LEAK:+$LEAK, }$(msg KIB_LEAK_HAPEER)"
  # Benutzernamen: nur plausible Namen (Payload-Zeilen enthalten keine Namen, sondern Kommandos)
  UNAMES=$(catlogs $(logs_in_window_all 'ns.log*') | grep -ao 'username: <[^>]*>' | sed 's/username: <//; s/>//' | grep -aE '^[A-Za-z0-9._@\\-]{3,64}$' | grep -vx USER | sort -u | head -500)
  for u in $UNAMES; do grep -aqF -- "$u" "$WORK/b2.txt" && { LEAK="${LEAK:+$LEAK, }$(msg KIB_LEAK_USERNAME)"; break; }; done
  if [ -n "$LEAK" ]; then
    echo "$(msg ERR_KIB_SELFCHECK_FAILED "$LEAK")" >&2
    grep -anE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$WORK/b2.txt" | head -3 | cut -c1-120 >&2
    exit 3
  fi
  mv "$BTMP" "$BFILE"; chmod 600 "$BFILE"
  echo "$(msg KIB_WRITTEN "$BFILE")"
  echo "$(msg KIB_COUNTS "$(grep -c '=' "$BFILE")" "$(grep -cvE '^#|^###|^$|=|<<<' "$BFILE")")"
  echo "$(msg KIB_SELFCHECK_OK)"
  echo "$(msg KIB_NO_CUSTOMER_DATA)"
  echo "$(msg KIB_DELETE_AFTER "$BFILE")"
  exit 0
fi

# --- Kopf ----------------------------------------------------------------------
out "$(msg HDR_RUN_LINE "$VERSION" "$HOST" "$MODE" "${HOURS}" "$RULES_VERSION" "$CLI_MODE" "${CLI_USER:+ ($CLI_USER${CFG_NOTE:+, $CFG_NOTE})}" "$(date '+%Y-%m-%d %H:%M:%S %Z')")" 1
[ "$MSG_LANG" != de ] && out "$(tagf TAG_INFO)$(msg HDR_LANG "$MSG_LANG" "$MSG_MISSING")" 1
[ "${CUSTOM_N:-0}" -gt 0 ] || [ "${CVE_CUSTOM_N:-0}" -gt 0 ] && out "$(tagf TAG_INFO)$(msg HDR_CUSTOM_LOADED "${CUSTOM_N:-0}" "${CVE_CUSTOM_N:-0}" "${CUSTOM_VERSION:-$(msg HDR_CUSTOM_NO_VERSION)}")" 1
[ "${CVE_CONFLICT_N:-0}" -gt 0 ] && out "$(tagf TAG_INFO)$(msg HDR_CVE_CONFLICT "${CVE_CONFLICT_N}" "$CVE_CONFLICTS")" 1
# Regelstand aelter als der Mindeststand des Scripts? (Stringvergleich ueber sort, Datum YYYY-MM-DD[x])
if [ "$RULES_VERSION" != "$RULES_MIN" ] && [ "$(printf '%s\n%s\n' "$RULES_VERSION" "$RULES_MIN" | sort | head -1)" = "$RULES_VERSION" ]; then
  out "$(tagf TAG_INFO)$(msg HDR_RULES_OLDER "$RULES_VERSION" "$RULES_MIN")" 1
fi
if [ "$TRUSTED_PRESENT" -eq 1 ]; then
  out "$(tagf TAG_INFO)$(msg HDR_TRUSTED_LIST "$TRUSTED_N" "$( [ "$TRUSTED_EXPIRED" -gt 0 ] && echo "$(msg HDR_TRUSTED_EXPIRED_FRAG "$TRUSTED_EXPIRED")")")" 1
  [ -n "$TRUSTED_BAD" ] && out "$(tagf TAG_WARN)$(msg HDR_TRUSTED_BAD_LINES "$TRUSTED_BAD")" 1
  cut -f1 "$TRUSTED_TAB" | while read -r _t; do _tb=$(echo "$_t" | sed 's#/.*##'); [ -n "$(blocked_info "$_tb")" ] && out "$(msg HDR_TRUSTED_AND_BLOCKED "$(tagf TAG_WARN)$_t")" 1; done
fi
if [ "${BLOCKED_PRESENT:-0}" -eq 1 ] || [ "${BLOCKED_N:-0}" -gt 0 ]; then
  out "$(tagf TAG_INFO)$(msg HDR_BLOCKED_LIST "$BLOCKED_N" "$( [ "${BLOCKED_NODATE:-0}" -gt 0 ] && echo "$(msg HDR_BLOCKED_NODATE_FRAG "${BLOCKED_NODATE}")")")" 1
  [ -n "$BLOCKED_BAD" ] && out "$(tagf TAG_WARN)$(msg HDR_BLOCKED_BAD_LINES "${BLOCKED_BAD}")" 1
fi
[ "${IOC_INACTIVE:-0}" -gt 0 ] && out "$(tagf TAG_INFO)$(msg HDR_IOC_INACTIVE "$IOC_INACTIVE")" 1
[ "$MODE" = offline ] && out "$(msg HDR_OFFLINE_SOURCE "$ROOT")" 1
[ "$CLI_MODE" = none ] && [ "$MODE" = online ] && out "$(msg HDR_CLI_OFF "${CLI_REASON:-$(msg HDR_CLI_REASON_NONE)}")" 1
if [ "$WL_OK" -eq 1 ]; then out "$(msg HDR_WHITELIST_LOADED "$WHITELIST_FILE" "$(grep -cvE '^#|^[[:space:]]*$' "$WHITELIST_FILE")")" 1
  _wlbad=$(grep -E '^webfile:' "$WHITELIST_FILE" | sed 's/@sha256=.*//' | grep -vE '\$$|/$' | sed 's/^webfile://' | head -5 | tr '\n' ' ')
  [ -n "$_wlbad" ] && out "$(tagf TAG_WARN)$(msg HDR_WL_WEBFILE_UNANCHORED "$_wlbad")" 1
  _wldir=$(grep -E '^webfile:.*/$' "$WHITELIST_FILE" | grep -c .); [ "$_wldir" -gt 0 ] && out "$(tagf TAG_INFO)$(msg HDR_WL_DIR_RULES "$_wldir")" 1
  _wlcode=$(grep -E '^webfile:' "$WHITELIST_FILE" | grep -v '@sha256=' | grep -iE '\\?\.(js|php|pl|sh|cgi|py)\$$|plugins\\?\.xml\$$' | sed 's/^webfile://' | head -5 | tr '\n' ' ')
  [ -n "$_wlcode" ] && out "$(tagf TAG_WARN)$(msg HDR_WL_CODE_NO_PIN "$_wlcode")" 1
else out "$(msg HDR_WHITELIST_MISSING "$WHITELIST_FILE")" 1; fi

# =============================================================================
if [ -n "$PIN_PATH" ]; then
  _pp="$ROOT${PIN_PATH}"; [ -e "$_pp" ] || { echo "$(msg ERR_PIN_NOT_FOUND "$PIN_PATH")" >&2; exit 3; }
  echo "$(msg PIN_HEAD "$( [ "$PIN_ALL" -eq 1 ] && echo $(msg PIN_SCOPE_ALL) || echo $(msg PIN_SCOPE_CODE))" "$PIN_PATH" "$(date '+%Y-%m-%d %H:%M')" "$VERSION")"
  find "$_pp" -type f 2>/dev/null | { if [ "$PIN_ALL" -eq 1 ]; then cat; else grep -iE '\.(js|php|pl|sh|cgi|py)$|/plugins\.xml$'; fi; } | sort | while IFS= read -r _f; do
    _h=$(sha256 -q "$_f" 2>/dev/null || sha256sum "$_f" 2>/dev/null | cut -c1-64); _rel="${_f#$ROOT}"; _esc=$(printf '%s' "$_rel" | sed 's/[.]/\\./g')
    printf 'webfile:^%s$@sha256=%s\n' "$_esc" "$_h"; done
  rm -rf "$WORK" 2>/dev/null; exit 0
fi
hdr "$(msg HDR_BLOCK1)"
# =============================================================================
BOOTFILE=""; BOOT=""; BUILD=""; CONFBUILD=""
if [ "$MODE" = online ]; then
  BOOTFILE=$(sysctl -n kern.bootfile 2>/dev/null); BOOT=$(sysctl -n kern.boottime 2>/dev/null | sed -nE 's/.*\{ *sec = ([0-9]+),.*/\1/p')
else
  BOOTFILE=$(awk -F'\t' '$1=="bootfile"{print $2}' "$META" 2>/dev/null); BOOT=$(awk -F'\t' '$1=="boottime_epoch"{print $2}' "$META" 2>/dev/null)
  [ -n "$BOOTFILE" ] || BOOTFILE=$(grep -m1 'kern.bootfile' "$STATE/sysctl_boot.txt" 2>/dev/null | awk '{print $2}')
fi
BUILD=$(echo "$BOOTFILE" | sed -nE 's/.*ns-([0-9]+\.[0-9]+)-([0-9]+\.[0-9]+).*/\1-\2/p')
CONFBUILD=$(head -n 5 "$NSCONF" | sed -nE 's/^#NS([0-9]+\.[0-9]+) Build ([0-9]+\.[0-9]+).*/\1-\2/p' | head -1)
[ -n "$BUILD" ] || { BUILD="$CONFBUILD"; inf "$(msg BUILD_FROM_NSCONF)" 1; }
REL=${BUILD%%-*}; BLD=${BUILD#*-}; BMAJ=${BLD%%.*}; BMIN=${BLD#*.}
ge() { _m=${1%%.*}; _n=${1#*.}; [ "$BMAJ" -gt "$_m" ] 2>/dev/null || { [ "$BMAJ" -eq "$_m" ] 2>/dev/null && [ "$BMIN" -ge "$_n" ] 2>/dev/null; }; }
TRAIN="$REL"; [ "$BMAJ" = 37 ] && TRAIN="$REL-FIPS"
# CVE-Tabelle: Bulletin|CVE|Train|Fix|Bedingung|Text. Fallback aus FIX_* (Slot A = all, Slot B = SAML).
if [ -z "$CVE_TABLE" ]; then
  mk() { set -- $2; [ -n "$1" ] && echo "CTX697096::CVE-2026-88771::$3::$1::all::$(msg BUILD_FALLBACK_TEXT_RCE)"; [ -n "$2" ] && echo "CTX697174::CVE-2026-88779::$3::$2::conf:^add authentication saml(Action|IdPProfile)::$(msg BUILD_FALLBACK_TEXT_SAML)"; }
  mk x "$FIX_14_1" 14.1 > "$WORK/cvefb.txt" 2>/dev/null; mk x "$FIX_13_1" 13.1 >> "$WORK/cvefb.txt" 2>/dev/null
  mk x "$FIX_14_1_FIPS" 14.1-FIPS >> "$WORK/cvefb.txt" 2>/dev/null; mk x "$FIX_13_1_FIPS" 13.1-FIPS >> "$WORK/cvefb.txt" 2>/dev/null
  CVE_TABLE=$(cat "$WORK/cvefb.txt")
fi
for _e in ${EOL_RELEASES:-}; do [ "$REL" = "$_e" ] && EOL=1; done
TAB=$(printf '\t')
ROWS=$(echo "$CVE_TABLE" | grep -v '^[[:space:]]*$' | grep -v '^#' | sed "s/::/$TAB/g" | awk -F"$TAB" -v t="$TRAIN" '$3==t')
NROWS=$(echo "$ROWS" | grep -c .)
FIXMAX=""; OPEN=""; NOPEN=0; NCOND=0
if [ -z "$BUILD" ]; then flag_yel "$(msg BUILD_UNKNOWN_YEL)"; VULN=1
elif [ "$EOL" -eq 1 ]; then flag_red "$(msg BUILD_EOL_RED "$REL" "$BUILD")"; VULN=1
elif [ "$NROWS" -eq 0 ]; then flag_yel "$(msg BUILD_TRAIN_UNKNOWN_YEL "$TRAIN" "$RULES_VERSION" "$BUILD")"
else
  echo "$ROWS" > "$WORK/rows.txt"
  while IFS="$TAB" read -r ctx cve train fix cond text; do
    if [ "$fix" = pending ]; then echo "OPEN $cve $ctx $train-pending $text $(msg BUILD_CVE_PENDING_FRAG "$RULES_VERSION")"; echo "$cond" | grep -qi saml && echo "SAMLOPEN $cve"; continue; fi
    echo "$fix" | grep -qE '^[0-9]+\.[0-9]+$' || { echo "$(msg BUILD_CVE_FIX_INVALID_FRAG "SKIP" "$ctx $cve" "$fix")"; continue; }
    applies=1; condnote=""
    case "$cond" in
      all) ;;
      conf:*) cg "${cond#conf:}" >/dev/null 2>&1 || applies=0; condnote="$(msg BUILD_CVE_COND_FRAG "${cond#conf:}")" ;;
      tcpparam:*) ;;
      *) applies=0 ;;
    esac
    if ge "$fix"; then
      case "$cond" in tcpparam:*) p="${cond#tcpparam:}"; cg '^set ns tcpParam ' | grep -qiE -- "-$p" || echo "ISN $cve $ctx $p" ;; esac
      echo "OK $cve $ctx $train-$fix"
    elif [ "$applies" -eq 1 ]; then echo "OPEN $cve $ctx $train-$fix $text$condnote"; echo "$cond" | grep -qi saml && echo "SAMLOPEN $cve"
    else echo "NA $cve $ctx $train-$fix (Bedingung nicht konfiguriert)"; fi
  done < "$WORK/rows.txt" > "$WORK/cve.txt"
  NOPEN=$(grep -c '^OPEN' "$WORK/cve.txt"); NOK=$(grep -c '^OK' "$WORK/cve.txt"); NNA=$(grep -c '^NA' "$WORK/cve.txt")
  FIXMAX=$(echo "$ROWS" | awk -F"$TAB" '$4 != "pending" {print $4}' | sort -t. -k1,1n -k2,2n | tail -1)
  if [ "$NOPEN" -gt 0 ]; then
    VULN=1
    grep '^OPEN' "$WORK/cve.txt" > "$WORK/open.txt"
    while read -r _ cve ctx fixb rest; do case "$fixb" in *-pending) flag_red "$(msg BUILD_VULN_NOFIX_RED "$BUILD" "$cve" "$ctx" "$rest")" ;; *) flag_red "$(msg BUILD_VULN_RED "$BUILD" "$cve" "$ctx" "$fixb" "$rest")" ;; esac; done < "$WORK/open.txt"
    grep -q '^SAMLOPEN ' "$WORK/cve.txt" && VULN9=1
    grep -q '^OPEN CVE-2026-1096[0-9]* CTX697263' "$WORK/cve.txt" && VULN63=1
    VULN96=0; grep -q '^OPEN CVE-2026-8877[0-9] CTX697096' "$WORK/cve.txt" && VULN96=1
    inf "$(msg BUILD_TARGET "$TRAIN" "$FIXMAX")" 1
  else
    _nc=$(echo "$ROWS" | grep -c '\[custom\]')
    _bx=$( [ "${_nc:-0}" -gt 0 ] && msg BUILD_FIX_SPLIT_FRAG "$((NOK - _nc))" "$_nc" || msg BUILD_FIX_RULES_FRAG ); _bn=$( [ "${NNA:-0}" -gt 0 ] && msg BUILD_FIX_NA_FRAG "$NNA" ); grn "$(msg BUILD_ALL_FIXED_OK "$BUILD" "$NOK" "$TRAIN" "$_bx" "$_bn")" 1
  fi
  grep '^SKIP' "$WORK/cve.txt" > "$WORK/skip.txt"; while read -r l; do flag_yel "$(msg BUILD_RULES_ROW_YEL "${l#SKIP }")"; done < "$WORK/skip.txt"
  grep '^ISN' "$WORK/cve.txt" | sed 's/^ISN //' > "$WORK/isn.txt"
fi
grep '^OPEN' "$WORK/cve.txt" 2>/dev/null | awk -v p="$(msg BUILD_VULN_JSON_PREFIX)" '{ sub(/^OPEN /, ""); print p " " $0 }' >> "$JRED"
grep '^OPEN' "$WORK/cve.txt" 2>/dev/null | awk -v p="$(msg BUILD_VULN_JSON_PREFIX)" '{ sub(/^OPEN /, ""); printf "R\t%s\n", p " " $0 }' >> "$JFIND"
if [ -n "$CONFBUILD" ] && [ -n "$BUILD" ] && [ "$CONFBUILD" != "$BUILD" ]; then
  flag_yel "$(msg BUILD_CONF_NOT_SAVED_YEL "$CONFBUILD" "$BUILD")"; SAVE_MISSING=1
fi
case "$REL" in 13.1) _w="$BUILD_WARN_13_1" ;; *) _w="" ;; esac
[ -n "$_w" ] && [ "${_w%%:*}" = "$BLD" ] && flag_yel "$(msg BUILD_WARN_YEL "$BUILD" "${_w#*:}")"
if [ "$MODE" = online ] && [ -n "$BOOT" ]; then
  NK=$(ls -t /flash/ns-*.gz 2>/dev/null | head -1)
  if [ -n "$NK" ]; then
    NKT=$(mtime_of "$NK"); NKB=$(basename "$NK" .gz); BFB=$(basename "$BOOTFILE" .gz)
    [ -n "$NKT" ] && [ "$NKT" -gt $((BOOT + 300)) ] && [ "$NKB" != "$BFB" ] && flag_yel "$(msg BUILD_STAGED_NOT_BOOTED_YEL "$(basename "$NK")" "$(fmtdate "$NKT")")"
  fi
fi
[ -n "$BOOT" ] && inf "$(msg BUILD_LAST_BOOT "$(fmtdate "$BOOT")" "$(( (NOW - BOOT) / 86400 ))")" 1

# =============================================================================
hdr "$(msg HDR_BLOCK2)"
# =============================================================================
S_SP=$(cgc '^add authentication samlAction '); S_IDP=$(cgc '^add authentication samlIdPProfile ')
if [ "${S_SP:-0}" -gt 0 ] || [ "${S_IDP:-0}" -gt 0 ]; then
  SAML=1
  if [ "$VULN9" -eq 1 ]; then inf "$(msg EXPO_SAML_CVE_OPEN "$S_SP" "$S_IDP")" 1
  else inf "$(msg EXPO_SAML "$S_SP" "$S_IDP")" 1; fi
else grn "$(msg EXPO_NO_SAML_OK)"; fi
DTLS=$(cg '^add vpn vserver [^ ]+ (SSL|DTLS) ' | grep -viE -- '-dtls OFF' | wc -l | tr -d ' ')
if [ "${DTLS:-0}" -gt 0 ]; then inf "$(msg EXPO_DTLS "$DTLS")" 1; else grn "$(msg EXPO_NO_DTLS_OK)"; fi
# Konfigurationsschritte aus der CVE-Tabelle (tcpparam:), die auf gefixtem Build noch offen sind
if [ -s "$WORK/isn.txt" ]; then
  if cg '^add (lb|cs|vpn|authentication|gslb|cr) vserver ' | grep -qiE ' (HTTP|SSL|TCP|SSL_TCP|SSL_BRIDGE) '; then
    while read -r cve ctx p; do flag_yel "$(msg EXPO_ISN_STEP_MISSING_YEL "$p" "$cve" "$ctx")"; ISN_OPEN=1; done < "$WORK/isn.txt"
  fi
else
  cg '^set ns tcpParam ' | grep -qiE -- '-enhancedISNGeneration ENABLED' && grn "$(msg EXPO_ISN_ACTIVE_OK)"
fi
PARTS=$(ls "$(dirname "$NSCONF")"/partitions/*/ns.conf 2>/dev/null | wc -l | tr -d ' ')
[ "${PARTS:-0}" -gt 0 ] && inf "$(msg EXPO_PARTITIONS "$PARTS")" 1
MG=$(cg '^add ns ip ' | grep -iE -- '-type SNIP' | grep -iE -- '-mgmtAccess ENABLED' | awk '{print $4}' | tr '\n' ' ' | sed 's/ $//')
[ -n "$MG" ] && flag_yel "$(msg EXPO_MGMT_ON_SNIP_YEL "$MG")"
# Management-Portal (PHP, CTX697263): Adressen und ACL-Mitigation
NSIP=$(cg '^set ns config ' | grep -oE -- '-IPAddress [0-9.]+' | awk '{print $2}' | head -1); [ -n "$NSIP" ] || NSIP=$(cg '^add ns ip ' | grep -iE -- '-type NSIP' | awk '{print $4}' | head -1)
MGMT_ADDRS="$NSIP $MG"; MGMT_ACL_OK=""; MGMT_ACL_NO=""
if [ -z "$(echo "$MGMT_ADDRS" | tr -d ' ')" ]; then inf "$(msg EXPO_MGMT_NSIP_UNKNOWN)" 1
elif [ -n "${MGMT_ACL_RE:-}" ]; then
  for _a in $MGMT_ADDRS; do [ -n "$_a" ] || continue; _re=$(echo "$MGMT_ACL_RE" | sed "s/NSIP_PLACEHOLDER/$(echo "$_a" | sed 's/\./\\./g')/")
    if cg "$_re" >/dev/null 2>&1; then MGMT_ACL_OK="$MGMT_ACL_OK$_a "; else MGMT_ACL_NO="$MGMT_ACL_NO$_a "; fi; done
  if [ "$VULN63" -eq 1 ] && [ -n "$MGMT_ACL_NO" ]; then flag_yel "$(msg EXPO_MGMT_NO_ACL_VULN_YEL "$MGMT_ACL_NO")"
  elif [ -n "$MGMT_ACL_NO" ]; then inf "$(msg EXPO_MGMT_NO_ACL_FIXED "$MGMT_ACL_NO")" 1
  else inf "$(msg EXPO_MGMT_ACL_OK "$MGMT_ACL_OK")" 1; fi
else inf "$(msg EXPO_MGMT_ACL_RULE_MISSING "$RULES_VERSION" "$RULES_MIN")" 1; fi

# =============================================================================
hdr "$(msg HDR_BLOCK3)"
# =============================================================================
RESP_ON=0; cg '^enable ns feature ' | grep -qiw RESPONDER && RESP_ON=1
PXN=$(cg '^add policy expression ' | grep -iE "$MITIGATION_RULE_RE" | awk '{print $4}' | tr -d '"' | tr '\n' '|' | sed 's/|$//')
POLRE="$MITIGATION_RULE_RE"; [ -n "$WL_MITIG" ] && POLRE="$POLRE|$WL_MITIG"; [ -n "$PXN" ] && POLRE="$POLRE|$PXN"
cg '^add responder policy ' | grep -iE "$POLRE" | awk '{print "responder " $4}' > "$WORK/mpol_raw.txt"
cg '^add vpn trafficPolicy ' | grep -iE "$POLRE" | awk '{print "traffic " $4}' >> "$WORK/mpol_raw.txt"
MPOL=$(tr -d '"' < "$WORK/mpol_raw.txt" | sort -u)
if [ -z "$MPOL" ]; then
  if [ "$VULN" -eq 1 ] || [ "$VULN9" -eq 1 ]; then flag_yel "$(msg MITIG_NONE_VULN_YEL)"
  else inf "$(msg MITIG_NONE)" 1; fi
else
  TMPM="$WORK/mitig"; : > "$TMPM"; echo "$MPOL" > "$WORK/mpol.txt"
  while read -r kind name; do
    BIND=$(grep -E "^bind (vpn|authentication) vserver .*-policy(Name)? \"?$name\"?( |\$)" "$NSCONF" 2>/dev/null)
    GLOB=$(grep -cE "^bind (responder|vpn) global \"?$name\"?( |\$)" "$NSCONF" 2>/dev/null); NB=$(echo "$BIND" | grep -c .)
    if [ "$NB" -eq 0 ] && [ "${GLOB:-0}" -eq 0 ]; then flag_yel "$(msg MITIG_POLICY_UNBOUND_YEL "$kind" "$name")"
    elif [ "$kind" = responder ]; then
      NAAA=$(echo "$BIND" | grep -ciE -- '-type AAA_REQUEST')
      if [ "$RESP_ON" -eq 0 ]; then flag_yel "$(msg MITIG_RESPONDER_OFF_YEL "$kind" "$name" "$NB")"
      elif [ "$NAAA" -eq 0 ] && [ "$NB" -gt 0 ]; then flag_yel "$(msg MITIG_NO_AAA_REQUEST_YEL "$kind" "$name" "$NB")"
      else grn "$(msg MITIG_RESPONDER_BOUND_OK "$kind" "$name" "$NB" "$NAAA" "${GLOB:+, global $GLOB}")"; echo "MITIG_OK" >> "$TMPM"; fi
    else grn "$(msg MITIG_POLICY_BOUND_OK "$kind" "$name" "$NB")"; echo "MITIG_OK" >> "$TMPM"; fi
    if [ "$CLI_MODE" != none ]; then
      # Hits aus "show <typ> policy <name>" (stat kuerzt Namen auf 12 Zeichen und ignoriert den Parameter)
      if [ "$kind" = responder ]; then H=$(cli "show responder policy $name" | sed -nE 's/^[[:space:]]*Hits:[[:space:]]*([0-9]+).*/\1/p' | head -1); else H=$(cli "show vpn trafficPolicy $name" | sed -nE 's/^[[:space:]]*Hits:[[:space:]]*([0-9]+).*/\1/p' | head -1); fi
      if [ -n "$H" ]; then
        echo "$name	$H" >> "$WORK/hits.tsv"
        PH=""; [ -n "$PREV_JSON" ] && PH=$(perl -ne 'if (/"'"$name"'":\s*"?(\d+)"?/) { print $1; exit }' "$PREV_JSON" 2>/dev/null)
        if [ -n "$PH" ]; then inf "$(msg MITIG_HITS_DELTA "$name" "$H" "$((H - PH))" "$PREV_TS")"; else inf "$(msg MITIG_HITS "$name" "$H")"; fi
      fi
    fi
  done < "$WORK/mpol.txt"
  grep -q MITIG_OK "$TMPM" && MITIG_OK=1
fi
if [ "$CLI_MODE" != none ] && [ "$SAML" -eq 1 ]; then
  if cli "stat denylist global AAA_REQUEST" | grep -qiE 'hits'; then inf "$(msg MITIG_DENYLIST_OK)" 1
  elif cli_missing; then inf "$(msg MITIG_DENYLIST_NONE)" 1; else inf "$(msg MITIG_DENYLIST_UNKNOWN)" 1; fi
fi

# =============================================================================
hdr "$(msg HDR_BLOCK4 "${HOURS}")"
# =============================================================================
MINS=$((HOURS * 60))
logs_in_window() { find "$LOGDIR" -maxdepth 1 -name "$1" -mmin -"$MINS" 2>/dev/null | sort; }
NSLOGS=$(logs_in_window 'ns.log*'; logs_in_window 'nsvpn.log*'; logs_in_window 'messages*'; logs_in_window 'notice.log*')
ERRLOGS=$(logs_in_window 'httperror*'); AUTHLOGS=$(logs_in_window 'auth.log*'); MGMTLOGS=$(logs_in_window 'httpaccess.log*'); CRONLOGS=$(logs_in_window 'cron*')
_lc() { echo "$1" | grep -c .; }
# net24_summary: liest "anzahl adresse" je Zeile von stdin, gibt "a.b.c.0/24 (n Adressen, m Requests)" absteigend aus
net24_summary() { awk '{ split($2, o, "."); if (o[4]=="") next; n=o[1] "." o[2] "." o[3] ".0/24"; a[n]++; r[n]+=$1 } END { for (n in a) printf "%s (%d Adresse(n), %d Request(s))\n", n, a[n], r[n] }' | sort -t'(' -k2 -rn | tr '\n' ' ' | sed 's/ $//'; }
# log_lines_in <datei-mit-zeilen> <dateien...>: "datei (n), ..." je Logdatei, wie viele der gefundenen Zeilen darin stehen
log_lines_in() { _lf="$1"; shift; for _f in "$@"; do [ -f "$_f" ] || continue; case "$_f" in *ns.log*|*nsvpn*|*messages*|*notice*) _n=$(catns "$_f" | grep -aFxc -f "$_lf") ;; *) _n=$(catlogs "$_f" | grep -aFxc -f "$_lf") ;; esac; [ "$_n" -gt 0 ] && printf '%s (%s), ' "$_f" "$_n"; done | sed 's/, $//'; }
# log_hits <ERE> <dateien...>: "datei (n), datei (n)" fuer die Zeile "Log:" im Befundblock
log_hits() { _re="$1"; shift; for _f in "$@"; do [ -f "$_f" ] || continue; case "$_f" in *ns.log*|*nsvpn*|*messages*|*notice*) _n=$(catns "$_f" | grep -acE "$_re") ;; *) _n=$(catlogs "$_f" | grep -acE "$_re") ;; esac; [ "$_n" -gt 0 ] && printf '%s (%s), ' "$_f" "$_n"; done | sed 's/, $//'; }
is_internal_ip() { case "$1" in 10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|127.*) return 0 ;; esac; [ -n "$MGMT_NET_RE" ] && echo "$1" | grep -qE "$MGMT_NET_RE" && return 0
  if is_trusted_ip "$1"; then trust_event "$1" "$(msg TRUST_EVT_INTERNAL)"; return 0; fi; return 1; }
ACCLOGS=$(logs_in_window 'httpaccess*')
# Obergrenze fuer Access-Logs: neueste zuerst, bis ACCESS_LOG_MAX_MB
if [ "${ACCESS_LOG_MAX_MB:-0}" -gt 0 ] && [ -n "$ACCLOGS" ]; then
  ACCLOGS=$(for f in $(ls -t $ACCLOGS 2>/dev/null); do echo "$f"; done | perl -ne 'BEGIN{$m=shift; $t=0} chomp; @s=stat($_); $t+=$s[7]; print "$_\n" if $t <= $m*1048576' "$ACCESS_LOG_MAX_MB")
fi
COVERAGE=full; COVERAGE_WHY=""; UNREAD=0
for _f in $NSLOGS $ACCLOGS $ERRLOGS $AUTHLOGS $MGMTLOGS; do [ -r "$_f" ] || UNREAD=$((UNREAD+1)); done
[ -z "$NSLOGS" ] && { COVERAGE=partial; COVERAGE_WHY="$COVERAGE_WHY$(msg TRACE_COV_NO_NSLOG_FRAG)"; }
[ -z "$ACCLOGS" ] && { COVERAGE=partial; COVERAGE_WHY="$COVERAGE_WHY$(msg TRACE_COV_NO_HTTPACCESS_FRAG)"; }
[ "$UNREAD" -gt 0 ] && { COVERAGE=partial; COVERAGE_WHY="$COVERAGE_WHY$(msg TRACE_COV_UNREADABLE_FRAG "$UNREAD")"; }
_npf=$(catlogs $NSLOGS | grep -ac 'nsprofmon_mgmt\.pl'); [ "${_npf:-0}" -gt 0 ] && inf "$(msg TRACE_NSPROF_DIVERTED "$_npf")" 1
inf "$(msg TRACE_LOGS_READ "$(_lc "$NSLOGS")" "$(_lc "$ACCLOGS")" "$(_lc "$ERRLOGS")" "$(_lc "$AUTHLOGS")" "$(_lc "$MGMTLOGS")" "$(_lc "$CRONLOGS")" "$( [ "$UNREAD" -gt 0 ] && echo "$(msg TRACE_LOGS_UNREADABLE_FRAG "$UNREAD")")")" 1
HOSTS=""
if [ -z "$NSLOGS" ]; then flag_yel "$(msg TRACE_NO_NSLOG_YEL "$LOGDIR")"
else
  INJ=$(catns $NSLOGS | grep -avE "$ADMIN_CMD_RE" | grep -aiE "$LOGON_HINT_RE" \
        | grep -aE "$TRIGGER_RE|$OBFUSC_RE|[;|&\`]([[:space:]]|%20)*($CMD_NAMES)([[:space:]<>;|&\`\$]|%20|%3B|\\\$|$)|(%3B|%7C|%26)($CMD_NAMES)(%20|%24|%3B|%7C|$)" | sort -u)
  NINJ=$(echo "$INJ" | grep -c .)
  if [ "$NINJ" -gt 0 ]; then
    FIRST=$(echo "$INJ" | head -1 | awk '{print $1,$2,$3}'); LAST=$(echo "$INJ" | tail -1 | awk '{print $1,$2,$3}')
    INJ_DATE=$(log_date "$(echo "$INJ" | tail -1)")
    # Abdeckung durch Sperrliste: alle Download-Hosts (und, falls bekannt, alle Quell-IPs) gesperrt vor dem Datum des letzten Versuchs
    INJ_COVERED=0
    if [ "$BLOCKED_N" -gt 0 ] && [ "$VULN" -eq 0 ]; then
      _hosts=$(echo "$INJ" | grep -oE '(https?://|ftp://|fetch |curl |wget )[^ "'"'"']*' | grep -oE '([0-9]+\.){3}[0-9]+' | sort -u); _all=1; _n=0
      for _h in $_hosts; do _n=$((_n+1)); blocked_covers "$_h" "${INJ_DATE:-9999-99-99}" || _all=0; done
      [ "$_n" -gt 0 ] && [ "$_all" -eq 1 ] && INJ_COVERED=1
    fi
    if [ "$INJ_COVERED" -eq 1 ]; then
      flag_org "$(msg TRACE_INJ_COVERED_ORG "$NINJ" "$FIRST" "$LAST")"
      for _h in $_hosts; do out "$(msg TRACE_INJ_COVERED_HOST_DET "          | $_h" "$(blocked_tag "$_h" | sed 's/^ (//; s/)$//')" "${INJ_DATE:-?}")" 1; done
      out "          | $(msg TRACE_INJ_COVERED_TODO_DET)" 1
    else
    TRACES=1
    flag_red "$(msg TRACE_INJ_RED "$NINJ" "$FIRST" "$LAST")"
    fi
    echo "$INJ" | LINE_MAX=0 show 5 1
    NPPE=$(echo "$INJ" | grep -oE '[0-9]+-PPE-[0-9]+' | sort -u | grep -c .)
    HOSTS=$(echo "$INJ" | sed -e 's/\${IFS}/ /g' -e 's/%24%7BIFS%7D/ /g' -e 's/%20/ /g' \
            | grep -aoiE '((fetch|curl|wget|tftp|nc)[[:space:]][^;|&]*|(https?|ftp)://[^;|&[:space:]]*)' \
            | grep -aoiE '(https?|ftp)://[A-Za-z0-9._-]+|(^|[[:space:]])([0-9]{1,3}\.){3}[0-9]{1,3}' \
            | sed -E -e 's#^[[:space:]]*##' -e 's#^[A-Za-z]+://##' | sort -u | head -10)
    for _h in $HOSTS; do echo "$_h" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' && ip_note payload_download_host "$_h" 1 "$(msg ADDR_SRC_INJ_LINE)"; done
    SRC=""
    # Quell-IP: Injection-Zeiten (Syslog, Appliance-Zeitzone) gegen Logon-Requests im Access-Log (eigener Offset).
    # Offset-Suche in 15-Minuten-Schritten; ein Offset != 0 gilt nur, wenn er mindestens 2 und mindestens die
    # Haelfte der Versuchszeiten trifft.
    if [ -n "$ACCLOGS" ]; then
      SRC_KIND=login; SRC_FILTER="\"(POST|GET) [^\"]*($LOGIN_PATH_RE)"
      # Responder-Zeilen: der Request kam nie beim Webserver an (kein Access-Log); Quelle steht in der Zeile, wenn die Policy sie protokolliert
      if echo "$INJ" | grep -aq 'RESPONDER'; then SRC_KIND=line
        SRC=$(echo "$INJ" | grep -aoiE '(from IP|Client_ip|CLIENT\.IP\.SRC|client ip|src_ip|srcip)[ :=]+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort | uniq -c | sort -rn | awk -v m="$(msg_raw TRACE_INJ_SRC_LINES_FRAG)" -v nin="$NINJ" '{ t=m; gsub(/%1/, $2, t); gsub(/%2/, $1, t); gsub(/%3/, nin, t); print $2 "\t-\t-\t" substr(t, length($2)+1) }')
      else
      SRC=$(catlogs $ACCLOGS | grep -aE "$SRC_FILTER" | INJ_LINES="$INJ" MSG_MATCH="$(msg_raw TRACE_INJ_SRC_MATCH_FRAG)" MSG_OFF="$(msg_raw TRACE_INJ_SRC_OFFSET_FRAG)" perl -MTime::Local -e '
        my %M=(Jan=>0,Feb=>1,Mar=>2,Apr=>3,May=>4,Jun=>5,Jul=>6,Aug=>7,Sep=>8,Oct=>9,Nov=>10,Dec=>11); my $now=time; my %t;
        for my $l (split /\n/, $ENV{INJ_LINES}) {
          next unless $l =~ /^([A-Z][a-z]{2})\s+(\d{1,2}) (\d\d):(\d\d):(\d\d) / && exists $M{$1};
          my $y=(localtime $now)[5]+1900; my $e=eval { timelocal($5,$4,$3,$2,$M{$1},$y) }; next unless defined $e;
          $e=timelocal($5,$4,$3,$2,$M{$1},$y-1) if $e > $now+86400; $t{$e}=1 }
        my @acc;
        while (<STDIN>) { next unless /^(\d+\.\d+\.\d+\.\d+)\s.*?\[(\d\d)\/([A-Z][a-z]{2})\/(\d{4}):(\d\d):(\d\d):(\d\d) ([+-])(\d\d)(\d\d)\]/ && exists $M{$3};
          my $ip=$1; my $e=eval { timegm($7,$6,$5,$2,$M{$3},$4) }; next unless defined $e; $e -= ($8 eq "-" ? -1 : 1)*($9*3600+$10*60); push @acc,[$ip,$e] }
        my $nt=scalar keys %t; my ($best,$bestn,%bh)=(0,-1);
        for my $off (0, map { ($_*900, -$_*900) } 1..56) {
          my %h; for my $a (@acc) { for my $d (-5..5) { my $k=$a->[1]+$d-$off; $h{$a->[0]}{$k}=1 if $t{$k} } }
          my %all; for my $ip (keys %h) { $all{$_}=1 for keys %{$h{$ip}} } my $n=scalar keys %all;
          if ($off==0 && $n>0) { ($best,$bestn)=(0,$n); %bh=%h; last }
          if ($n>$bestn) { ($best,$bestn)=($off,$n); %bh=%h } }
        if ($best!=0 && ($bestn<2 || $bestn*2<$nt)) { %bh=(); $bestn=0 }
        for my $ip (sort { scalar(keys %{$bh{$b}}) <=> scalar(keys %{$bh{$a}}) } keys %bh) {
          my $n=scalar keys %{$bh{$ip}}; my $o=""; if ($best) { $o=$ENV{MSG_OFF}; my $h=sprintf("%g", abs($best)/3600); $o =~ s/%1/$h/ } my $t=$ENV{MSG_MATCH}; $t =~ s/%1/$ip/; $t =~ s/%2/$n/; $t =~ s/%3/$nt/; $t =~ s/%4/$o/; print "$ip\t$n\t$nt\t" . substr($t, length($ip)) . "\n" }
      ' 2>/dev/null | head -5)
      fi
      [ -n "$SRC" ] && echo "$SRC" | cut -f1 | while read -r _ip; do if [ "$SRC_KIND" = line ]; then ip_note injection_source "$_ip" 1 "$(msg ADDR_SRC_RESPONDER_LINE)"; else ip_note injection_source "$_ip" 1 "$(msg ADDR_SRC_LOGON_AT_ATTEMPT)"; fi; done
    fi
    # Befundblock: Wann, Ergebnis, Download-Host, Quelle, Zu tun
    out "          | $(msg TRACE_INJ_WHEN_DET "$FIRST" "$LAST" "$NINJ" "${NPPE:-?}" "$( [ "${NPPE:-0}" -gt 1 ] && echo "$(msg TRACE_INJ_ONE_WAVE_FRAG)")")" 1
    echo "$INJ" > "$WORK/inj_lines.txt"; out "          | $(msg TRACE_LOG_DET "$(log_lines_in "$WORK/inj_lines.txt" $NSLOGS)")" 1
    if [ "$VULN" -eq 1 ]; then out "          | $(msg TRACE_INJ_RESULT_VULN_DET "$BUILD")" 1
    elif [ "$INJ_COVERED" -eq 1 ]; then out "          | $(msg TRACE_INJ_RESULT_COVERED_DET)" 1
    else out "          | $(msg TRACE_INJ_RESULT_NO_EFFECT_DET "$BUILD" "$( [ "${MITIG_OK:-0}" -eq 1 ] && echo "$(msg TRACE_INJ_MITIG_ANSWERED_FRAG)")")" 1
      [ "$SAML" -eq 1 ] && [ "$VULN9" -eq 1 ] && out "          | $(msg TRACE_INJ_SAML_CAUTION_DET)" 1; fi
    if [ -n "$HOSTS" ]; then
      for _h in $HOSTS; do
        _bi=$(blocked_info "$_h"); _bl="$(msg TRACE_NO)"; [ -n "$_bi" ] && { _s=$(echo "$_bi" | cut -d'|' -f2); _bl="$(msg TRACE_YES)"; [ -n "$_s" ] && _bl="$_bl$(msg TRACE_BLOCKED_SINCE_FRAG "$_s")"; }
        _rs=$(ioc_src_raw ip "$_h"); _rl="$(msg TRACE_NO)"; [ -n "$_rs" ] && _rl="$(msg TRACE_RULES_YES_FRAG "$_rs")"
        out "          | $(msg TRACE_INJ_DLHOST_DET "$_h" "$_bl" "$_rl")$(expired_tag "$_h")" 1
      done
    else out "          | $(msg TRACE_INJ_DLHOST_NONE_DET)" 1; fi
    if [ -n "$SRC" ]; then
      # Felder: ip, Treffer, Versuchszeiten, Text; leere Zahlen stehen als "-", weil Tabs als IFS-Whitespace zusammenfallen
      echo "$SRC" | while IFS="$(printf '\t')" read -r _ip _n _mt _ld; do _w=""; case "$_mt" in ''|-) ;; *) [ "$_mt" -gt 1 ] && [ "${_n:-0}" -eq 1 ] && _w="$(msg TRACE_SRC_WEAK_FRAG)" ;; esac; _ld=$(echo "$_ld" | sed 's/^ *//')
          if [ "$SRC_KIND" = line ]; then _same=""; echo "$HOSTS" | grep -qx "$_ip" && _same="$(msg TRACE_SRC_SAME_AS_DLHOST_FRAG)"; out "          | $(msg TRACE_INJ_SRC_RESPONDER_DET "$_ip" "$_ld" "$_same" "$(blocked_tag "$_ip")" "$(trusted_tag "$_ip")")" 1
          else out "          | $(msg TRACE_INJ_SRC_ACCESS_DET "$_ip" "$_ld" "$_w" "$(blocked_tag "$_ip")" "$(trusted_tag "$_ip")")" 1; fi; done
    elif [ "$SRC_KIND" = line ]; then out "          | $(msg TRACE_INJ_SRC_UNKNOWN_RESP_DET)" 1
    elif [ -n "$ACCLOGS" ]; then out "          | $(msg TRACE_INJ_SRC_UNKNOWN_NOREQ_DET)" 1
    else out "          | $(msg TRACE_INJ_SRC_UNKNOWN_NOLOG_DET)" 1; fi
    if [ "$VULN" -eq 1 ]; then
      out "          | $(msg TRACE_INJ_TODO_VULN1_DET)" 1
      out "          | $(msg TRACE_INJ_TODO_VULN2_DET)" 1
    elif [ "$INJ_COVERED" -eq 1 ]; then out "          | $(msg TRACE_TODO_NOTHING_BLOCK_DET)" 1
    else
      _z=1
      for _h in $HOSTS; do out "          | $(msg TRACE_INJ_TODO_FW_DET "$_z" "$_h" "$FIRST")" 1; _z=$((_z+1)); break; done
      [ -z "$SRC" ] && [ "$SRC_KIND" != line ] && { out "          |$(msg TRACE_INJ_TODO_FETCH_LOG_DET " $_z" "$FIRST")" 1; _z=$((_z+1)); }
      [ -z "$SRC" ] && [ "$SRC_KIND" = line ] && { out "          |$(msg TRACE_INJ_TODO_RESP_AUDIT_DET " $_z" "$FIRST")" 1; _z=$((_z+1)); }
      [ -n "$HOSTS" ] && out "          |$(msg TRACE_INJ_TODO_BLOCK_HOST_DET " $_z")" 1
    fi
  else grn "$(msg TRACE_INJ_NONE_OK "${HOURS}")"; fi
  # --- Prozessabstuerze (Pitboss und Kernel): Ereignisse je Prozess und PID, Restart-Zaehler, Core-Verzeichnisse
  if [ -n "${PITBOSS_RE:-}" ] && [ -n "${KERNEL_EXIT_RE:-}" ]; then
    catns $NSLOGS | grep -aE "$PITBOSS_RE|$KERNEL_EXIT_RE" > "$WORK/crash_lines.txt"
    # Apache-Worker-Abstuerze aus dem Webserver-Fehlerlog (Format "[Thu Oct 23 10:01:00.100000 2026] [core:notice] [pid 1200] AH00052: child pid 1234 exit signal Segmentation fault (11)")
    [ -n "${HTTPERR_CRASH_RE:-}" ] && catlogs $ERRLOGS | grep -aE "$HTTPERR_CRASH_RE" >> "$WORK/crash_lines.txt"
    # Zeile -> datum TAB zeit TAB proc TAB pid TAB art TAB wert   (art: died|signal|restart|restarts|escalate)
    perl -e '
      my %M=(Jan=>"01",Feb=>"02",Mar=>"03",Apr=>"04",May=>"05",Jun=>"06",Jul=>"07",Aug=>"08",Sep=>"09",Oct=>"10",Nov=>"11",Dec=>"12"); my $cy=(localtime)[5]+1900;
      # Zeit einheitlich aus dem Syslog-Kopf (Lokalzeit der Appliance); die GMT-Angabe der PPE-Zeilen nur, wenn der Kopf fehlt
      while (<STDIN>) { chomp; my ($d,$t)=("",""); if (/^([A-Z][a-z]{2}) +(\d+) (\d\d:\d\d:\d\d)/) { $d=sprintf("%04d-%s-%02d",$cy,$M{$1},$2); $t=$3 } elsif (m{(\d\d)/(\d\d)/(\d{4}):(\d\d:\d\d:\d\d)}) { $d="$3-$1-$2"; $t=$4 }
        if (/^\[([A-Z][a-z]{2}) ([A-Z][a-z]{2}) +(\d+) (\d\d:\d\d:\d\d)(?:\.\d+)? (\d{4})\]/) { $d=sprintf("%04d-%s-%02d",$5,$M{$2},$3); $t=$4 }
        if (/AH00052: child pid (\d+) exit signal [A-Za-z ]+ \((\d+)\)/) { print "$d\t$t\thttpd\t$1\tsignal\t$2\n"; next }
        if (/kernel: pid (\d+) \(([^)]+)\), jid \d+, uid \d+: exited on signal (\d+)/) { print "$d\t$t\t$2\t$1\tsignal\t$3\n"; next }
        if (/(\S+) \((\d+)\) unexpectedly died/) { print "$d\t$t\t$1\t$2\tdied\t\n"; next }
        if (/collecting core dump on (\S+) \((\d+)\)/) { print "$d\t$t\t$1\t$2\tdied\t\n"; next }
        if (/kernel: Core dump of pid (\d+) \(([^)]+)\)/) { print "$d\t$t\t$2\t$1\tdied\t\n"; next }
        if (/Adding pitboss watch on \((\d+)\) for \(/) { next }
        if (/pitboss\[\d+\]: proc (\S+) \((\d+)\) SIGNALED/) { print "$d\t$t\t$1\t$2\tdied\t\n"; next }
        if (/pitboss\[\d+\]: proc (\S+) \((\d+)\) EXITED with status 0x([0-9a-f]+)/) { my $st=hex($3); my $sig=($st>=128 ? $st-128 : 0); print "$d\t$t\t$1\t$2\t".($sig>0 ? "status" : "died")."\t$sig\n"; next }
        if (/Restarting process (\S+) old pid \((\d+)\)/) { print "$d\t$t\t$1\t$2\trestart\t\n"; next }
        if (/New pid \((\d+)\) for \(([^)]+)\) restarts \((\d+)\)/) { print "$d\t$t\t$2\tnew\trestarts\t$3\n"; next }
        if (/maximum number of restarts|declaring system failure/i) { print "$d\t$t\t?\t?\tescalate\t$_\n"; next } }' < "$WORK/crash_lines.txt" > "$WORK/crash.tsv"
    # Ereignis = Prozess + gestorbene PID + Tag; Restart-Zaehler je Prozess als Hoechstwert; Eskalation als eigenes Ereignis
    # Ereignis = Prozess + gestorbene PID + Tag; Restart-Zaehler je Ereignis aus der naechsten "New pid ... restarts (n)"-Zeile desselben Prozesses
    sort -t"$(printf '\t')" -k1,1 -k2,2 "$WORK/crash.tsv" | awk -F'\t' -v mesc="$(msg TRACE_CRASH_ESCALATION_FRAG)" '
      $5=="died" || $5=="signal" || $5=="restart" || $5=="status" { k=$3 SUBSEP $4 SUBSEP $1; if (!(k in ev)) { ev[k]=1; ord[++n]=k; ep[k]=$3; eid[k]=$4; ed[k]=$1; et[k]=$2; pend[$3]=k } if ($5=="signal") es[k]=$6; if ($5=="status" && es[k]=="") es[k]=$6; if ($2 < et[k] || et[k]=="") et[k]=$2 }
      $5=="restarts" { if ($3 in pend) { rs[pend[$3]]=$6+0; delete pend[$3] } }
      $5=="escalate" { k="ESC" SUBSEP ++m; ord[++n]=k; ep[k]="(Pitboss)"; eid[k]="-"; ed[k]=$1; et[k]=$2; es[k]=mesc " " $6 }
      END { for (i=1;i<=n;i++) { k=ord[i]; printf "%s %s\t%s\t%s\t%s\t%s\n", ed[k], et[k], ep[k], eid[k], (es[k]==""?"-":es[k]), (k in rs ? rs[k] : "-") } }' | sort -r > "$WORK/crash_events.tsv"
    NCR=$(grep -c . "$WORK/crash_events.tsv")
    # Core-Verzeichnisse im Fenster (auch ohne Logzeile, etwa nach Rotation)
    # Core-Belege: Verzeichnisse /var/core/<n> (aelteres Muster) und Dateien /var/core/<proc>-<pid> (Standardmuster %N-%P)
    if [ "$MODE" = online ]; then CORED=$(find /var/core -mindepth 1 -maxdepth 1 \( -type d -o -type f \) -mmin -"$MINS" 2>/dev/null | grep -v '/bounds$' | sort)
    elif [ -f "$MANIFEST" ]; then CORED=$(awk -F'\t' -v s="$(( $(date +%s) - MINS*60 ))" '$1 ~ /^\/var\/core\/[^\/]+$/ && $1 !~ /\/bounds$/ && $7 >= s { print $1 }' "$MANIFEST" | sort); else CORED=""; fi
    NCORED=$(echo "$CORED" | grep -c .)
    # Core-Datei ohne Logzeile ist selbst ein Ereignis (Logrotation, nicht ueberwachter Prozess)
    : > "$WORK/core_boot.txt"
    echo "$CORED" | grep . | while IFS= read -r _cf; do _cb=$(basename "$_cf"); _cb=${_cb%.gz}; _cb=${_cb%.bz2}; _cb=${_cb%.xz}
      _cm=$( [ "$MODE" = online ] && mtime_of "$_cf" || awk -F'\t' -v f="$_cf" '$1==f {print $7}' "$MANIFEST" 2>/dev/null); _cm=${_cm:-0}
      _ct="$(fmtdate "$_cm" | sed 's/ [0-9:]*$//') $(fmtdate "$_cm" | awk '{print $2}'):00"
      if echo "$_cb" | grep -qE '^[0-9]+$'; then
        # nummeriertes Verzeichnis: Prozess unbekannt; leer und kurz nach dem Boot = Boot-Nachlauf
        _empty=1; if [ "$MODE" = online ]; then [ -d "$_cf" ] && [ -n "$(ls -A "$_cf" 2>/dev/null)" ] && _empty=0; else awk -F'\t' -v d="$_cf/" 'index($1,d)==1 { f=1 } END { exit f ? 0 : 1 }' "$MANIFEST" 2>/dev/null && _empty=0; fi
        _sb=$(( _cm - ${BOOT:-0} ))
        if [ "$_empty" -eq 1 ] && [ "$_sb" -ge 0 ] && [ "$_sb" -le 900 ] && [ "${CORE_BOOT_LEVEL:-info}" != yellow ]; then printf '%s\t%s\t%s\n' "$_cf" "$_ct" "$((_sb / 60))" >> "$WORK/core_boot.txt"; continue; fi
        _de=$( [ "$_empty" -eq 1 ] && msg TRACE_CRASH_DIR_EMPTY_FRAG ); printf '%s\t%s\t-\t%s\t-\n' "$_ct" "$(msg TRACE_CRASH_PROC_UNKNOWN)" "$(msg TRACE_CRASH_DIR_EVENT_FRAG "$_cf" "$_de" "$((_sb / 60))")" >> "$WORK/crash_events.tsv"; continue
      fi
      _cp=${_cb%-*}; _cpid=${_cb##*-}; echo "$_cpid" | grep -qE '^[0-9]+$' || { _cp="$_cb"; _cpid="-"; }
      grep -q "	$_cp	$_cpid	" "$WORK/crash_events.tsv" 2>/dev/null && continue
      printf '%s\t%s\t%s\t%s\t-\n' "$_ct" "$_cp" "$_cpid" "$(msg TRACE_CRASH_CORE_NOLOG_FRAG)" >> "$WORK/crash_events.tsv"; done
    sort -r "$WORK/crash_events.tsv" -o "$WORK/crash_events.tsv"; NCR=$(grep -c . "$WORK/crash_events.tsv")
    # Boot-Cores (INFO) sind keine Belege: aus Liste und Zaehler nehmen; der Gelb-Block oeffnet nur mit Ereignissen
    if [ -s "$WORK/core_boot.txt" ]; then cut -f1 "$WORK/core_boot.txt" > "$WORK/core_boot_paths.txt"; CORED=$(echo "$CORED" | grep -vxF -f "$WORK/core_boot_paths.txt"); fi
    NCORED=$(echo "$CORED" | grep -c .)
    if [ "$NCR" -gt 0 ]; then
      TRACES=1
      _nsa=$(awk -F'\t' '$2=="nsaaad"' "$WORK/crash_events.tsv" | grep -c .); _htd=$(awk -F'\t' '$2=="httpd"' "$WORK/crash_events.tsv" | grep -c .); _ppe=$(awk -F'\t' '$2 ~ /^nsppe|^NSPPE/' "$WORK/crash_events.tsv" | grep -c .)
      _ddt=0; catns $NSLOGS | grep -aqE "$DTLS_FAIL_RE" && _ddt=1
      # Haeufung: je Prozess Ereignisse in 24 h (Fenster) und an verschiedenen Tagen (kumulierte Datei)
      _max24=$(awk -F'\t' '{ split($1,a," "); c[$2 SUBSEP a[1]]++ } END { m=0; for (k in c) if (c[k]>m) m=c[k]; print m+0 }' "$WORK/crash_events.tsv")
      _nsa24=$(awk -F'\t' '$2=="nsaaad" { split($1,a," "); c[a[1]]++ } END { m=0; for (k in c) if (c[k]>m) m=c[k]; print m+0 }' "$WORK/crash_events.tsv")
      CUMC="$(dirname "${OUTFILE:-.}")/ns_quickcheck_observed_crashes.tsv"; _days3=""
      awk -F'\t' '{ split($1,a," "); print $2 "\t" a[1] }' "$WORK/crash_events.tsv" > "$WORK/crash_days.tsv"
      if [ -f "$CUMC" ]; then _days3=$(grep -v '^#' "$CUMC" | cat - "$WORK/crash_days.tsv" | sort -u | awk -F'\t' '{ d[$1]++ } END { for (p in d) if (d[p] >= 3) printf "%s ", p }'); fi
      # Korrelation: SAML-Anfrage oder externer Management-Request in den 120 s vor einem nsaaad-/httpd-Absturz
      _trig=""
      while IFS="$(printf '\t')" read -r _ct _cp _cpid _rest; do
        case "$_cp" in nsaaad|httpd) ;; *) continue ;; esac
        _ce=$(perl -MTime::Local -e 'my ($d,$t)=split / /,$ARGV[0]; my ($y,$m,$dd)=split /-/,$d; my ($H,$Mi,$S)=split /:/,$t; print timelocal($S,$Mi,$H,$dd,$m-1,$y)' "$_ct" 2>/dev/null); [ -n "$_ce" ] || continue
        # Zeilen der 120 s vor dem Ereignis: Syslog-Zeit (nsaaad: SAML-Zeilen in ns.log) bzw. Apache-Zeit (httpd: Management-Access-Log)
        if [ "$_cp" = nsaaad ]; then
          _hit=$(catns $NSLOGS | grep -aE 'SAML|AssertionConsumerService|SAMLResponse' | before_syslog "$_ce" 120 | grep -oE 'Client_ip [0-9.]+|from [0-9.]+' | cut -d' ' -f2 | grep -v '^$' | sort | uniq -c | sort -rn | head -1 | sed 's/^ *[0-9]* //')
        else
          _hit=$(catlogs $MGMTLOGS | before_apache "$_ce" 120 | cut -d' ' -f1 | sort -u | while read -r _mi; do is_internal_ip "$_mi" || echo "$_mi"; done | head -1)
        fi
        [ -n "$_hit" ] && { _trig="$_trig$(msg TRACE_CRASH_TRIG_FRAG "$_cp" "$_cpid" "$_hit") "; ip_note crash_trigger "$_hit" 1 "$(msg ADDR_SRC_CRASH_TRIGGER "$_cp")"; }
      done < "$WORK/crash_events.tsv"
      _hd=$(msg TRACE_CRASH_HEAD "$NCR" "$( [ "$NCORED" -gt 0 ] && msg TRACE_CRASH_CORES_FRAG "$NCORED" )")
      _why=""
      [ "$_nsa" -gt 0 ] && [ "$SAML" -eq 1 ] && [ "$VULN9" -eq 1 ] && _why="$(msg TRACE_CRASH_WHY_SAML_VULN)"
      [ -z "$_why" ] && [ "$_nsa24" -ge 2 ] && [ "$SAML" -eq 1 ] && _why="$(msg TRACE_CRASH_WHY_NSAAAD_REPEAT "$_nsa24")"
      [ -z "$_why" ] && [ "$_htd" -gt 0 ] && [ "$VULN63" -eq 1 ] && _why="$(msg TRACE_CRASH_WHY_HTTPD_VULN)"
      [ -z "$_why" ] && [ "$_ppe" -gt 0 ] && [ "$_ddt" -eq 1 ] && _why="$(msg TRACE_CRASH_WHY_PPE_DTLS)"
      [ -z "$_why" ] && [ "$_max24" -ge 3 ] && _why="$(msg TRACE_CRASH_WHY_SAME_DAY "$_max24")"
      [ -z "$_why" ] && [ -n "$_days3" ] && _why="$(msg TRACE_CRASH_WHY_THREE_DAYS "$_days3")"
      [ -z "$_why" ] && [ -n "$_trig" ] && _why="$(msg TRACE_CRASH_WHY_TRIGGER "$_trig")"
      if [ -n "$_why" ]; then flag_red "$(msg TRACE_CRASH_RED "$_hd" "$_why")"
      else flag_yel "$(msg TRACE_CRASH_YEL "$_hd" "$( [ "$_nsa" -gt 0 ] && [ "$SAML" -eq 1 ] && msg TRACE_CRASH_NSAAAD_SAML_FRAG )" "$( [ "$_htd" -gt 0 ] && msg TRACE_CRASH_HTTPD_FRAG )")"; fi
      [ -n "$_trig" ] && [ -n "$_why" ] && out "          | $(msg TRACE_CRASH_TRIGGER_DET "$_trig")" 1
      # kumulierte Absturzdatei je Appliance: Prozess TAB Tag, fuer die Wiederholung ueber Tage
      if [ -n "${OUTFILE:-}" ] && [ "$NO_OUT" -eq 0 ]; then { [ -f "$CUMC" ] && grep -v '^#' "$CUMC"; awk -F'\t' '{ split($1,a," "); print $2 "\t" a[1] }' "$WORK/crash_events.tsv"; } | sort -u > "$WORK/cumc.tmp"; { echo "$(msg TRACE_CRASHFILE_HEAD)"; cat "$WORK/cumc.tmp"; } > "$CUMC"; chmod 600 "$CUMC" 2>/dev/null; fi
      out "          | $(msg TRACE_CRASH_EVENTS_DET)" 1
      awk -F'\t' -v cores="$(echo "$CORED" | tr '\n' ' ')" -v mrow="$(msg_raw TRACE_CRASH_EVENT_ROW)" -v mcore="$(msg_raw TRACE_CRASH_EVENT_CORE_FRAG)" 'function m(t,a,b,c,d,e,f) { gsub(/%1/,a,t); gsub(/%2/,b,t); gsub(/%3/,c,t); gsub(/%4/,d,t); gsub(/%5/,e,t); gsub(/%6/,f,t); return t } { c=""; n=split(cores, a, " "); for (i=1;i<=n;i++) { b=a[i]; sub(/\.(gz|bz2|xz)$/, "", b); if (b ~ ("/" $2 "-" $3 "$")) c=m(mcore, a[i]) } if ($3=="-") printf "%s  %s  %s\n", $1, $2, $4; else print m(mrow, $1, $2, $3, $4, $5, c) }' "$WORK/crash_events.tsv" | show 10 1
      [ "$NCORED" -gt 0 ] && { out "          | $(msg TRACE_CRASH_CORES_DET)" 1; echo "$CORED" | show 10 1; }
      [ "$NCR" -gt 0 ] && out "          | $(msg TRACE_LOG_DET "$(log_lines_in "$WORK/crash_lines.txt" $NSLOGS)")" 1
      out "          | $(msg TRACE_CRASH_WHAT_DET)" 1
      out "          | $(msg TRACE_CRASH_TODO_DET)" 1
    else grn "$(msg TRACE_CRASH_NONE_OK)"; fi
    [ -s "$WORK/core_boot.txt" ] && while IFS="$(printf '\t')" read -r _cf _ct _mn; do inf "$(msg TRACE_CORE_BOOT "$_cf" "$_ct" "$_mn" "$_cf")" 1; done < "$WORK/core_boot.txt"
    NCRASH=${NCR:-0}
    # Kernel: Panic/Trap und Speicherdruck
    if [ -n "${KERNEL_PANIC_RE:-}" ]; then _kp=$(catns $NSLOGS | grep -aE "$KERNEL_PANIC_RE" | grep -c .); [ "$_kp" -gt 0 ] && { TRACES=1; flag_red "$(msg TRACE_KERNEL_PANIC_RED "$_kp")"; catns $NSLOGS | grep -aE "$KERNEL_PANIC_RE" | tail -3 | show 3 1; }; fi
    if [ -n "${KERNEL_MEM_RE:-}" ]; then _km=$(catns $NSLOGS | grep -aE "$KERNEL_MEM_RE" | grep -c .); [ "$_km" -gt 0 ] && { TRACES=1; flag_yel "$(msg TRACE_KERNEL_MEM_YEL "$_km")"; catns $NSLOGS | grep -aE "$KERNEL_MEM_RE" | tail -3 | show 3 1; }; fi
    # Neustart ohne reboot/shutdown im Audit-Log (Panic, Watchdog, Stromverlust oder Angreifer)
    if [ -n "${BOOT:-}" ] && [ "$BOOT" -gt 0 ] && [ "$((NOW - BOOT))" -le "$((HOURS * 3600))" ]; then
      # nur bewertbar, wenn Logzeilen aus der Zeit vor dem Boot vorliegen (sonst fehlt die Vorgeschichte, keine Aussage)
      _pre=$(catns $NSLOGS | before_syslog "$BOOT" 86400 | grep -c .)
      _rb=$(catns $NSLOGS | before_syslog "$BOOT" 3600 | grep -aiE 'CMD_EXECUTED.*(reboot|shutdown|"reboot"|restart)|SHELL shell_command=(reboot|shutdown)|shutdown\[[0-9]+\]: (reboot|halt)|syslogd: exiting on signal 15' | grep -c .); [ "$_pre" -eq 0 ] && _rb=1
      [ "$_rb" -eq 0 ] && { TRACES=1; flag_yel "$(msg TRACE_REBOOT_UNEXPLAINED_YEL "$(fmtdate "$BOOT")")"; }
    fi
    # altes, weites Muster: Treffer nur dort = unbekanntes Format, einsenden
    if [ -n "${NSAAAD_CRASH_LEGACY_RE:-}" ]; then
      _leg=$(catns $NSLOGS | grep -aiE "$NSAAAD_CRASH_LEGACY_RE" | grep -avE "$PITBOSS_RE|$KERNEL_EXIT_RE" | grep -c .)
      [ "$_leg" -gt 0 ] && inf "$(msg TRACE_NSAAAD_UNKNOWN_FORMAT "$_leg" "$BUILD")" 1
    fi
  elif [ -n "${NSAAAD_CRASH_RE:-}" ]; then
    # Rueckfall fuer Regeldateien vor 2026-10-27
    SC=$(catns $NSLOGS | grep -aiE "$NSAAAD_CRASH_RE" | sort -u); NSC=$(echo "$SC" | grep -c .)
    if [ "$NSC" -gt 0 ]; then TRACES=1; flag_yel "$(msg TRACE_NSAAAD_LEGACY_YEL "$NSC" "$RULES_VERSION")"; echo "$SC" | tail -5 | show 5 1
    else grn "$(msg TRACE_NSAAAD_LEGACY_NONE_OK)"; fi
  else inf "$(msg TRACE_CRASH_RULES_MISSING "$RULES_VERSION")" 1; fi
  # --- CPU-Momentaufnahmen (nsprofmon_mgmt.pl): verdaechtige Prozesse mit Zeitstempel, Block 5 sieht nur den Moment des Laufs
  if [ -s "$NSPROF_FILE" ] && [ -n "${SUSPECT_PROC_RE:-}" ]; then
    _sp=$(grep -aE "$SUSPECT_PROC_RE" "$NSPROF_FILE" | grep -av 'ns_quickcheck' | sort -u); _nsp=$(echo "$_sp" | grep -c .)
    if [ "$_nsp" -gt 0 ]; then TRACES=1; flag_yel "$(msg TRACE_NSPROF_SUSPECT_YEL "$_nsp")"; echo "$_sp" | tail -5 | show 5 1
    else grn "$(msg TRACE_NSPROF_NONE_OK)"; fi
  fi
# Dropper-Transportpfade je Quell-IP (DROPPER_PATH_RE): legitime Downloads, aber im Angriffskontext relevant
if [ -z "$ACCLOGS" ]; then inf "$(msg TRACE_NO_ACCESSLOG "${HOURS}")" 1; fi
if [ -n "$DROPPER_PATH_RE" ] && [ -n "$ACCLOGS" ]; then
  catlogs $ACCLOGS | grep -aE "\"(GET|POST) [^\"]*($DROPPER_PATH_RE)" | awk '{print $1}' | sort | uniq -c | sort -rn > "$WORK/drop.txt"
  if [ -s "$WORK/drop.txt" ]; then
    NDROP=$(grep -c . "$WORK/drop.txt"); DROP_RED=0
    while read -r _cnt _ip; do ip_note dropper_requester "$_ip" "$_cnt" "$(msg ADDR_SRC_DROPPER)"; done < "$WORK/drop.txt"
    if [ "${NINJ:-0}" -gt 0 ]; then
      while read -r cnt ip; do echo "$INJ" | grep -qF -- "$ip" && DROP_RED=1; done < "$WORK/drop.txt"
    fi
    # Sperrliste: je Adresse Datum des letzten Requests; gesperrt vor dem letzten Request = abgedeckt (ORANGE),
    # gesperrt aber Requests danach = Sperre greift nicht (GELB); nicht gesperrt = Bewertung wie bisher
    # vertraute Adressen: aus dem Befund heraus, in den [TRUST]-Block
    awk -v t="$(cut -f1 "$TRUSTED_TAB" | tr '\n' ' ')" 'BEGIN { n=split(t, a, " ") } { keep=1; for (i=1;i<=n;i++) { ip=a[i]; sub(/\/.*/, "", ip); if ($2==ip) keep=0 } if (keep) print }' "$WORK/drop.txt" > "$WORK/drop2.txt" && mv "$WORK/drop2.txt" "$WORK/drop.txt"
    DROP_COV=""; DROP_LEAK=""; DROP_OPENLIST=""; DROP_NODATE=""; DROP_COVD=""; DROP_LEAKD=""
    while read -r _cnt _ip; do
      if [ "$BLOCKED_N" -gt 0 ] && [ -n "$(blocked_info "$_ip")" ]; then
        _last=$(catlogs $ACCLOGS | grep -aE "^$_ip " | grep -aE "\"(GET|POST) [^\"]*($DROPPER_PATH_RE)" | tail -1); _d=$(log_date "$_last")
        if [ -z "$_d" ]; then DROP_OPENLIST="$DROP_OPENLIST$_ip "; DROP_NODATE="$DROP_NODATE$_ip "
        elif blocked_covers "$_ip" "$_d"; then DROP_COV="$DROP_COV$_ip "; DROP_COVD="$DROP_COVD$_ip=$_d "
        elif [ -z "$(echo "$(blocked_info "$_ip")" | cut -d'|' -f2)" ]; then DROP_OPENLIST="$DROP_OPENLIST$_ip "
        else DROP_LEAK="$DROP_LEAK$_ip "; DROP_LEAKD="$DROP_LEAKD$_ip=$_d:$_cnt "; fi
      else DROP_OPENLIST="$DROP_OPENLIST$_ip "; fi
    done < "$WORK/drop.txt"
    if [ -n "$DROP_COV" ]; then
      flag_org "$(msg TRACE_DROP_COVERED_ORG)"
      for _ip in $DROP_COV; do _ld=$(echo "$DROP_COVD" | tr ' ' '\n' | grep "^$_ip=" | cut -d= -f2); out "$(msg TRACE_DROP_COVERED_DET "          | $_ip" "$(blocked_tag "$_ip" | sed 's/^ (//; s/)$//')" "$_ld" "$(awk -v i="$_ip" '$2==i {print $1}' "$WORK/drop.txt")")" 1; done
      out "          | $(msg TRACE_DROP_COVERED_TODO_DET)" 1
    fi
    [ -n "$DROP_LEAK" ] && { flag_yel "$(msg TRACE_DROP_BLOCK_LEAK_YEL)"
      for _ip in $DROP_LEAK; do _x=$(echo "$DROP_LEAKD" | tr ' ' '\n' | grep "^$_ip=" | cut -d= -f2); out "$(msg TRACE_DROP_BLOCK_LEAK_DET "          | $_ip" "$(blocked_tag "$_ip" | sed 's/^ (//; s/)$//')" "${_x#*:}" "${_x%%:*}")" 1; done
      out "          | $(msg TRACE_DROP_BLOCK_LEAK_TODO_DET)" 1; }
    [ -n "$DROP_NODATE" ] && out "          | $(msg TRACE_DROP_NODATE_DET "$DROP_NODATE")" 1
    if [ -n "$DROP_OPENLIST" ]; then
    # Dropper-Suche: je nicht gesperrter Adresse die angefragten Paketnamen; mehr als zwei verschiedene oder ein Query-String mit Kommandozeichen = kein Client
    catlogs $ACCLOGS | grep -aE "\"(GET|POST) [^\"]*($DROPPER_PATH_RE)" | awk '{ for (i=1;i<=NF;i++) if ($i ~ /^"(GET|POST)$/) { print $1 "\t" $(i+1); break } }' | sort -u > "$WORK/droppaths.txt"
    DROP_HUNT=$(awk -F'\t' -v open=" $DROP_OPENLIST" 'index(open, " " $1 " ")==0 { next } { p=$2; q=""; if (index(p,"?")) { q=substr(p,index(p,"?")+1); p=substr(p,1,index(p,"?")-1) } sub(/.*\//,"",p); n[$1 SUBSEP p]=1
      if (q ~ /echo|%20|\$|;|\||`|%24|%3B|%7C/) bad[$1]=1 }
      END { for (k in n) { split(k, a, SUBSEP); c[a[1]]++ } for (ip in c) if (c[ip] > 2 || (ip in bad)) printf "%s ", ip }' "$WORK/droppaths.txt")
    if [ -n "$DROP_HUNT" ]; then DROP_RED=1; fi
    NOPEN_IP=$(echo "$DROP_OPENLIST" | wc -w | tr -d ' ')
    if [ "$DROP_RED" -eq 1 ]; then TRACES=1; flag_red "$(msg TRACE_DROP_HUNT_RED)"
      [ -n "$DROP_HUNT" ] && out "          | $(msg TRACE_DROP_HUNT_DET "$DROP_HUNT")" 1
    else flag_yel "$(msg TRACE_DROP_YEL "$NOPEN_IP")"; fi
    _dfirst=$(catlogs $ACCLOGS | grep -aE "\"(GET|POST) [^\"]*($DROPPER_PATH_RE)" | grep -oE '\[[0-9]+/[A-Za-z]+/[0-9]+:[0-9:]+' | sort | head -1 | tr -d '['); _dlast=$(catlogs $ACCLOGS | grep -aE "\"(GET|POST) [^\"]*($DROPPER_PATH_RE)" | grep -oE '\[[0-9]+/[A-Za-z]+/[0-9]+:[0-9:]+' | sort | tail -1 | tr -d '[')
    out "          | $(msg TRACE_WHEN_DET "${_dfirst:-?}" "${_dlast:-?}")" 1
    _lh=$(log_hits "\"(GET|POST) [^\"]*($DROPPER_PATH_RE)" $ACCLOGS); out "          | $(msg TRACE_LOG_DET "$_lh")" 1
    for _ip in $DROP_OPENLIST; do
      _cnt=$(awk -v i="$_ip" '$2==i {print $1}' "$WORK/drop.txt"); _bi=$(blocked_info "$_ip"); _bl="$(msg TRACE_NO)"; [ -n "$_bi" ] && { _s=$(echo "$_bi" | cut -d'|' -f2); if [ -n "$_s" ]; then _bl="$(msg TRACE_YES)$(msg TRACE_BLOCKED_SINCE_FRAG "$_s")"; else _bl="ja$(msg TRACE_BLOCKED_NODATE_FRAG)"; fi; }
      _rs=$(ioc_src_raw ip "$_ip"); _rl="$(msg TRACE_NO)"; [ -n "$_rs" ] && _rl="$(msg TRACE_RULES_YES_FRAG "$_rs")"
      _hunt="$(msg TRACE_NO)"; case " $DROP_HUNT" in *" $_ip "*) _hunt="$(msg TRACE_YES)" ;; esac
      out "          | $(msg TRACE_DROP_ADDR_DET "$_ip" "$_cnt" "$_hunt" "$_bl" "$_rl")$(expired_tag "$_ip")" 1
    done
    [ "$(grep -c . "$WORK/drop.txt")" -gt 1 ] && out "          | $(msg TRACE_NETS_DET "$(net24_summary < "$WORK/drop.txt")")" 1
    if [ -n "$DROP_HUNT" ]; then out "          | $(msg TRACE_DROP_RESULT_HUNT_DET)" 1
    else out "          | $(msg TRACE_DROP_RESULT_OPEN_DET)" 1; fi
    _z=1
    [ -n "$DROP_HUNT" ] && { out "          | $(msg TRACE_DROP_TODO_BLOCK_DET "$_z")" 1; _z=$((_z+1)); out "          |$(msg TRACE_DROP_TODO_FIELD_DET " $_z")" 1; _z=$((_z+1)); }
    [ -z "$DROP_HUNT" ] && { out "          | $(msg TRACE_DROP_TODO_CHECK_DET "$_z")" 1; _z=$((_z+1)); }
    out "          |$(msg TRACE_DROP_TODO_PATHS_DET " $_z")" 1
    catlogs $ACCLOGS | grep -aE "\"(GET|POST) [^\"]*($DROPPER_PATH_RE)" | awk -v open=" $DROP_OPENLIST" 'index(open, " " $1 " ")==0 { next } { for (i=1;i<=NF;i++) if ($i ~ /^"(GET|POST)$/) { print $1 "  " $(i+1); break } }' | sort | uniq -c | sort -rn | awk '{print $2"  "$3"  ("$1"x)"}' | show 8 1
    fi
  fi
fi
  if catns $NSLOGS | grep -aqE "$DTLS_FAIL_RE" && catns $NSLOGS | grep -aqE "$PPE_CRASH_RE"; then
    TRACES=1; flag_red "$(msg TRACE_DTLS_PPE_RED)"
    out "          | $(msg TRACE_LOG_DET "$(log_hits "$DTLS_FAIL_RE|$PPE_CRASH_RE" $NSLOGS)")" 1
  fi
  # --- Webserver-Fehlerlog: (a) Interpreter-Fehler, (b) Sondierung von Webshell-Namen, (c) Client ausserhalb 127.0.0.x
  if [ -z "$ERRLOGS" ]; then inf "$(msg TRACE_NO_ERRLOG "${HOURS}")" 1
  elif [ -z "${HTTPERR_EXEC_RE:-}" ] || [ -z "${HTTPERR_PROBE_RE:-}" ]; then inf "$(msg TRACE_ERRLOG_RULES_MISSING "$RULES_VERSION" "$RULES_MIN")" 1
  else
    HX=$(catlogs $ERRLOGS | grep -aE "$HTTPERR_EXEC_RE" | grep -avE '/netscaler/ns_gui/admin_ui/|/var/netscaler/gui/admin_ui/' | sort | uniq -c | sort -rn | head -30)
    NHX=$(echo "$HX" | grep -c .)
    if [ "$NHX" -gt 0 ]; then TRACES=1; flag_red "$(msg TRACE_HTTPERR_EXEC_RED "$NHX")"
      echo "$HX" | awk '{ c=$1; $1=""; sub(/^ /,""); print $0 "  (" c "x)" }' | show 8 1
      out "          | $(msg TRACE_LOG_DET "$(log_hits "$HTTPERR_EXEC_RE" $ERRLOGS)")" 1
      out "          | $(msg TRACE_HTTPERR_EXEC_RESULT_DET)" 1
      out "          | $(msg TRACE_HTTPERR_EXEC_TODO_DET)" 1
    else grn "$(msg TRACE_HTTPERR_EXEC_NONE_OK)"; fi
    # PHP-Speicher- und Fatal-Muster im Management-Portal (CTX697263), auch im admin_ui; Heuristik mit Schwelle
    PHP_ANOM=0
    if [ -n "${HTTPERR_PHP_ANOMALY_RE:-}" ]; then
      catlogs $ERRLOGS | grep -aE "$HTTPERR_PHP_ANOMALY_RE" > "$WORK/php_anom.txt"; PHP_ANOM=$(grep -c . "$WORK/php_anom.txt")
      if [ "$PHP_ANOM" -ge "${PHP_ANOMALY_MIN:-3}" ]; then
        _pa1=$(log_date "$(head -1 "$WORK/php_anom.txt")"); _pa2=$(log_date "$(tail -1 "$WORK/php_anom.txt")")
        if [ "$VULN63" -eq 1 ]; then flag_yel "$(msg TRACE_PHP_ANOM_VULN_YEL "$PHP_ANOM" "${_pa1:-?}" "${_pa2:-?}")"
        else inf "$(msg TRACE_PHP_ANOM_FIXED "$PHP_ANOM" "${_pa1:-?}" "${_pa2:-?}")" 1; fi
        sort "$WORK/php_anom.txt" | uniq -c | sort -rn | awk '{ c=$1; $1=""; sub(/^ /,""); print $0 "  (" c "x)" }' | show 6 1
        out "          | $(msg TRACE_LOG_DET "$(log_hits "$HTTPERR_PHP_ANOMALY_RE" $ERRLOGS)")" 1
        out "          | $(msg TRACE_PHP_ANOM_RESULT_DET)" 1
        [ "$VULN63" -eq 1 ] && out "          | $(msg TRACE_PHP_ANOM_TODO_DET)" 1
      else grn "$(msg TRACE_PHP_ANOM_NONE_OK "${PHP_ANOMALY_MIN:-3}")"; fi
    else inf "$(msg TRACE_PHP_ANOM_RULE_MISSING "$RULES_VERSION" "$RULES_MIN")" 1; fi
    # Sondierung: Webshell-Namen aus der Regel plus Dateinamen aus PAYLOAD_PATHS
    PN=$(for _p in $PAYLOAD_PATHS; do basename "$_p"; done | sort -u | sed 's/[.[\*^$]/\\&/g' | tr '\n' '|' | sed 's/|$//')
    PROBE_RE="$HTTPERR_PROBE_RE"; [ -n "$PN" ] && PROBE_RE="$HTTPERR_PROBE_RE|File does not exist: .*/($PN)$"
    # Webshell-Pfad mit Status 200 im Access-Log: die Datei hat geantwortet
    if [ -n "$ACCLOGS" ]; then
      WS200=$(catlogs $ACCLOGS | grep -aE "\"(GET|POST) [^\" ]*(/\.ctxs[^/ \"?]*|/\.local_journal|/\.slap[^/ \"?]*|/\.nsmon|/\.ux$( [ -n "$PN" ] && echo "|/($PN)"))([ ?\"][^\"]*)? HTTP/[0-9.]+\" 200 " | sort | uniq -c | sort -rn | head -10)
      if [ -n "$WS200" ]; then TRACES=1; COMPROMISE=1; flag_red "$(msg TRACE_WEBSHELL_200_RED)"
        echo "$WS200" | awk '{ c=$1; $1=""; sub(/^ /,""); print $0 "  (" c "x)" }' | LINE_MAX=0 show 10 1
        echo "$WS200" | awk '{print $2}' | sort -u | while read -r _ip; do ip_note webshell_hit "$_ip" 1 "$(msg ADDR_SRC_WEBSHELL_200)"; done
        out "          | $(msg TRACE_WEBSHELL_200_TODO_DET)" 1; fi
    fi
    HP=$(catlogs $ERRLOGS | grep -aE "$PROBE_RE" | grep -oE 'File does not exist: [^ ]+' | sed 's/^File does not exist: //' | sort | uniq -c | sort -rn)
    NHP=$(echo "$HP" | grep -c .)
    if [ "$NHP" -gt 0 ]; then
      HPL=$(catlogs $ERRLOGS | grep -aE "$PROBE_RE"); NPROBE=$(echo "$HPL" | grep -c .)
      # Zeitspanne chronologisch: Apache-Zeilen beginnen mit "[Thu Oct 23 ...]", Textsortierung ist keine Zeitsortierung
      _pdates=$(echo "$HPL" | while IFS= read -r _hl; do log_date "$_hl"; done | grep -E '^[0-9]{4}-' | sort); _pd1=$(echo "$_pdates" | head -1); _pd2=$(echo "$_pdates" | tail -1)
      # Quellen: dieselben Pfade im Access-Log (Client-Adresse dort), je Adresse Anzahl, Sperrstatus
      PSRC=""
      if [ -n "$ACCLOGS" ]; then
        _paths=$(echo "$HP" | awk '{print $2}' | sed 's#^/var/netscaler/logon#/logon#; s#^/netscaler/ns_gui#/#; s#^/var/netscaler/gui#/#' | sed 's/[.[\*^$]/\\&/g' | tr '\n' '|' | sed 's/|$//')
        [ -n "$_paths" ] && PSRC=$(catlogs $ACCLOGS | grep -aE "\"(GET|POST) [^\" ]*($_paths)" | awk '{print $1}' | sort | uniq -c | sort -rn | head -20)
        PSRC=$(echo "$PSRC" | while read -r _c _ip; do [ -n "$_ip" ] || continue; if is_trusted_ip "$_ip"; then ip_note webshell_probe "$_ip" "$_c" "$(msg ADDR_SRC_WEBSHELL_PROBE_TRUSTED)"; else echo "$_c $_ip"; fi; done)
      fi
      _lvl="${PROBE_LEVEL:-yellow}"
      if [ "$_lvl" = "info" ]; then inf "$(msg TRACE_PROBE "$NPROBE" "$NHP")" 1
      else flag_yel "$(msg TRACE_PROBE_YEL "$NPROBE" "$NHP")"; fi
      echo "$HP" | awk '{ print $2 "  (" $1 "x)" }' | show 10 1
      out "          | $(msg TRACE_WHEN_DET "${_pd1:-?}" "${_pd2:-?}")" 1
      out "          | $(msg TRACE_LOG_DET "$(log_hits "$PROBE_RE" $ERRLOGS)")" 1
      out "          | $(msg TRACE_PROBE_NOTE_DET)" 1
      if [ -n "$PSRC" ]; then
        echo "$PSRC" | while read -r _c _ip; do [ -n "$_ip" ] || continue; ip_note webshell_probe "$_ip" "$_c" "$(msg ADDR_SRC_WEBSHELL_PROBE)"; out "          | $(msg TRACE_PROBE_SRC_DET "$_ip" "$_c" "$(blocked_tag "$_ip")")" 1; done
        [ "$(echo "$PSRC" | grep -c .)" -gt 1 ] && out "          | $(msg TRACE_NETS_DET "$(echo "$PSRC" | net24_summary)")" 1
        _withsrc=$(echo "$PSRC" | awk '{ s+=$1 } END { print s+0 }'); [ "$NPROBE" -gt "$_withsrc" ] && out "$(msg TRACE_PROBE_NO_SRC_DET "          | $((NPROBE - _withsrc))")" 1
      else out "          | $(msg TRACE_PROBE_SRC_UNKNOWN_DET)" 1; fi
      out "          | $(msg TRACE_PROBE_RESULT_DET)" 1
      out "          | $(msg TRACE_PROBE_TODO_DET)" 1
    else grn "$(msg TRACE_PROBE_NONE_OK)"; fi
    # Client ausserhalb 127.0.0.x: direkter Zugriff am Gateway vorbei
    HC=$(catlogs $ERRLOGS | grep -aoE '\[client [0-9.]+:' | grep -vE '\[client 127\.0\.0\.' | sed 's/\[client //; s/:$//' | sort | uniq -c | sort -rn | head -10)
    if [ -n "$HC" ]; then flag_yel "$(msg TRACE_WEBSERVER_DIRECT_YEL)"; echo "$HC" | awk '{print $2 " (" $1 "x)"}' | show 8 1
      echo "$HC" | awk '{print $2}' | while read -r _ip; do is_internal_ip "$_ip" || ip_note webserver_direct "$_ip" 1 "$(msg ADDR_SRC_HTTPERR_CLIENT)"; done
      out "          | $(msg TRACE_WEBSERVER_DIRECT_RESULT_DET)" 1
      out "          | $(msg TRACE_WEBSERVER_DIRECT_TODO_DET)" 1; fi
  fi
  # --- Management-Ebene: Zugriffe auf NITRO und GUI von aussen (httpaccess.log der NSIP)
  if [ -z "$MGMTLOGS" ]; then inf "$(msg TRACE_NO_MGMTLOG "${HOURS}")" 1
  elif [ -z "${MGMT_PATH_RE:-}" ]; then inf "$(msg TRACE_MGMT_RULE_MISSING "$RULES_VERSION" "$RULES_MIN")" 1
  else
    MG=$(catlogs $MGMTLOGS | grep -aE "$MGMT_PATH_RE" | awk '{print $1}' | sort | uniq -c | sort -rn)
    MGX=$(echo "$MG" | while read -r _c _ip; do [ -n "$_ip" ] || continue; is_internal_ip "$_ip" || printf '%s\t%s\n' "$_ip" "$_c"; done)
    if [ -n "$MGX" ]; then
      flag_yel "$(msg TRACE_MGMT_EXTERNAL_YEL)"
      echo "$MGX" | while IFS="$(printf '\t')" read -r _ip _c; do ip_note mgmt_access "$_ip" "$_c" "$(msg ADDR_SRC_MGMT_PATH)"; echo "$(msg TRACE_MGMT_ADDR_FRAG "$_ip" "$_c")$(blocked_tag "$_ip")"; done | show 8 1
      out "          | $(msg TRACE_LOG_DET "$(log_hits "$MGMT_PATH_RE" $MGMTLOGS)")" 1
      out "          | $(msg TRACE_MGMT_EXTERNAL_RESULT_DET)" 1
      out "          | $(msg TRACE_MGMT_EXTERNAL_TODO_DET)" 1
    else grn "$(msg TRACE_MGMT_INTERNAL_OK)"; fi
  fi
  # --- Anmeldungen an der Appliance (auth.log): Logins von aussen, Backdoor-Konten, Brute Force
  if [ -z "$AUTHLOGS" ]; then inf "$(msg TRACE_NO_AUTHLOG "${HOURS}")" 1
  elif [ -z "${AUTH_LOGIN_RE:-}" ]; then inf "$(msg TRACE_AUTH_RULES_MISSING "$RULES_VERSION" "$RULES_MIN")" 1
  else
    AL=$(catlogs $AUTHLOGS | grep -aE "$AUTH_LOGIN_RE" | grep -oE 'for [^ ]+ from [0-9.]+|as [^ ]+' | sed 's/^for //; s/^as /console /' | grep -v '#nsinternal#' | sort | uniq -c | sort -rn)
    AF=$(catlogs $AUTHLOGS | grep -aE "$AUTH_FAIL_RE" | grep -oE 'from [0-9.]+' | awk '{print $2}' | sort | uniq -c | sort -rn | awk '$1 >= 10 { print $2 "\t" $1 }')
    AL_EXT=$(echo "$AL" | awk '{ print $2, $4 }' | while read -r _u _ip; do [ -n "$_ip" ] || continue; is_internal_ip "$_ip" || echo "$(msg TRACE_SSH_USER_FROM_FRAG "$_u" "$_ip")"; done)
    AL_BD=$(echo "$AL" | awk '{print $2}' | grep -E '^(sec_monitor|gw_health)$' | sort -u)
    if [ -n "$AL_BD" ]; then TRACES=1; COMPROMISE=1; flag_red "$(msg TRACE_SSH_BACKDOOR_RED "$(echo "$AL_BD" | tr '\n' ' ')")"; echo "$AL" | grep -E "$(echo "$AL_BD" | tr '\n' '|' | sed 's/|$//')" | show 5 1; fi
    if [ -n "$AL_EXT" ]; then flag_yel "$(msg TRACE_SSH_EXTERNAL_YEL)"; echo "$AL_EXT" | show 8 1
      echo "$AL_EXT" | awk '{print $NF}' | sort -u | while read -r _ip; do ip_note ssh_login_external "$_ip" 1 "$(msg ADDR_SRC_AUTH_ACCEPTED)"; done
      out "          | $(msg TRACE_SSH_EXTERNAL_TODO_DET)" 1; fi
    if [ -n "$AF" ]; then flag_yel "$(msg TRACE_SSH_BRUTEFORCE_YEL)"; echo "$AF" | while IFS="$(printf '\t')" read -r _ip _c; do msg TRACE_SSH_FAIL_FRAG "$_ip" "$_c"; echo; done | show 8 1
      echo "$AF" | while IFS="$(printf '\t')" read -r _ip _c; do ip_note ssh_bruteforce "$_ip" "$_c" "$(msg ADDR_SRC_AUTH_FAILED)"; done
      out "          | $(msg TRACE_SSH_BRUTEFORCE_TODO_DET)" 1; fi
    [ -n "$AL" ] && [ -z "$AL_EXT" ] && [ -z "$AL_BD" ] && inf "$(msg TRACE_SSH_INTERNAL_ONLY "$(echo "$AL" | awk '{ if ($2=="console") s = s "console:" $3 " (" $1 ") "; else s = s $2 " (" $1 ") " } END { print s }')")" 1
    [ -n "$AL" ] && { catlogs $AUTHLOGS | grep -aE "$AUTH_LOGIN_RE" | grep -v '#nsinternal#' > "$WORK/al_lines.txt"; out "          | $(msg TRACE_LOG_DET "$(log_lines_in "$WORK/al_lines.txt" $AUTHLOGS)")" 1; }
    [ -z "$AL" ] && [ -z "$AF" ] && grn "$(msg TRACE_AUTH_NONE_OK)"
  fi
  # --- Gateway-Anmeldefehler (AAA): je Adresse Takt, Konten, Zeitraum, Erfolg danach; Mensch/Maschine; Treffer = Rot
  if [ -z "${AAA_FAIL_RE:-}" ] || [ -z "${AAA_OK_RE:-}" ]; then inf "$(msg AAA_RULES_MISSING "$RULES_VERSION" "$RULES_MIN")" 1
  elif [ -n "$NSLOGS" ]; then
    catns $NSLOGS | grep -aE "$AAA_FAIL_RE|$AAA_OK_RE" | grep -avE "$ADMIN_CMD_RE" > "$WORK/aaa_all.txt"
    # eigene Adressen: ns.conf (ns ip, vserver, server, HA, serverIP) mit Objektname; dazu RFC 1918 und MGMT_NET_RE zur Laufzeit
    : > "$WORK/own_ips.txt"
    if [ -r "$NSCONF" ]; then
      cg '^add ns ip6? ' | awk '{print $4 "\tns ip"}' >> "$WORK/own_ips.txt"
      cg '^add (lb|cs|vpn|authentication|gslb|cr) vserver ' | awk '$5 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $5 "\t" $4}' >> "$WORK/own_ips.txt"
      cg '^add server ' | awk '$4 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $4 "\tserver " $3}' >> "$WORK/own_ips.txt"
      cg '^add HA node ' | awk -v m="$(msg AAA_OWN_HAPEER)" '{print $5 "\t" m}' >> "$WORK/own_ips.txt"
      cg ' -serverIP ' | sed 's/.*-serverIP \([0-9.]*\).*/\1/' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | awk '{print $1 "\tserverIP"}' >> "$WORK/own_ips.txt"
    fi
    own_obj() { awk -F'\t' -v i="$1" '$1==i { print $2; exit }' "$WORK/own_ips.txt"; }
    # Zeilen -> "epoch TAB ok|fail TAB ip TAB user" (Zeit aus "MM/DD/YYYY:HH:MM:SS" oder "YYYY/MM/DD:HH:MM:SS" der Zeile, sonst Syslog-Zeit)
    AAA_FAIL_RE="$AAA_FAIL_RE" AAA_OK_RE="$AAA_OK_RE" perl -MTime::Local -e '
      my %M=(Jan=>0,Feb=>1,Mar=>2,Apr=>3,May=>4,Jun=>5,Jul=>6,Aug=>7,Sep=>8,Oct=>9,Nov=>10,Dec=>11); my $now=time; my $cy=(localtime $now)[5]+1900;
      while (<STDIN>) { chomp; my $k = /$ENV{AAA_FAIL_RE}/ ? "fail" : (/$ENV{AAA_OK_RE}/ ? "ok" : next);
        my $e;
        if (/(\d\d)\/(\d\d)\/(\d\d\d\d):(\d\d):(\d\d):(\d\d)/) { $e=eval { timegm($6,$5,$4,$2,$1-1,$3) } }
        elsif (/(\d\d\d\d)\/(\d\d)\/(\d\d):(\d\d):(\d\d):(\d\d)/) { $e=eval { timegm($6,$5,$4,$3,$2-1,$1) } }
        elsif (/^([A-Z][a-z][a-z]) +(\d\d?) (\d\d):(\d\d):(\d\d) / && exists $M{$1}) { $e=eval { timelocal($5,$4,$3,$2,$M{$1},$cy) }; $e=timelocal($5,$4,$3,$2,$M{$1},$cy-1) if defined $e && $e > $now+86400 }
        next unless defined $e;
        my ($ip,$u)=("",""); $ip=$1 if /(?:Client_ip|from|Clientip|client_ip)[ :=]+(\d+\.\d+\.\d+\.\d+)/i; $u=$1 if /(?:User|user:|for user|user)[ :=]+([^ \s"]+)/;
        next unless $ip; print "$e\t$k\t$ip\t$u\n" }' < "$WORK/aaa_all.txt" | sort -n > "$WORK/aaa.tsv"
    NAF=$(awk -F'\t' '$2=="fail"' "$WORK/aaa.tsv" | grep -c .)
    if [ "$NAF" -gt 0 ]; then
      # je Adresse: fail, konten, erster, letzter, max/min, erfolg-danach (gleiches Konto, innerhalb AAA_OK_WIN nach letztem Fehlversuch), Konten-Beispiele
      awk -F'\t' -v win="$(( ${AAA_OK_WIN:-5} * 60 ))" -v rate="${AAA_RATE:-10}" -v fip="${AAA_FAIL_IP:-5}" -v fus="${AAA_FAIL_USERS:-10}" -v sld="${AAA_SLEEPER_DAYS:-2}" '
        $2=="fail" { f[$3]++; k=$3 SUBSEP $4; if (!(k in seen)) { seen[k]=1; users[$3]++; ul[$3]=(ul[$3]=="" ? $4 : ul[$3] "," $4) } if (!($3 in first)) first[$3]=$1; last[$3]=$1; lf[k]=$1; m=$3 SUBSEP int($1/60); pm[m]++; if (pm[m]>mx[$3]) mx[$3]=pm[m]; uf[$4]++
                     dk=$3 SUBSEP int($1/86400); if (!(dk in dseen)) { dseen[dk]=1; days[$3]++ }
                     if (!(k in useen)) { useen[k]=1; uips[$4]++; uipl[$4]=(uipl[$4]=="" ? $3 : uipl[$4] "," $3) } if (!($4 in ufirst)) ufirst[$4]=$1; ulast[$4]=$1; um=$4 SUBSEP int($1/60); upm[um]++; if (upm[um]>umx[$4]) umx[$4]=upm[um] }
        $2=="ok"   { k=$3 SUBSEP $4; if ((k in lf) && $1>=lf[k] && $1-lf[k]<=win) { okA[$3]++; okU[$4]=1; okL[$3]=(okL[$3]=="" ? $4 : okL[$3] "," $4) }
                     if (($4 in ulast) && $1>=ulast[$4] && $1-ulast[$4]<=win) { uokAny[$4]=1; uokIp[$4]=$3 } }
        END {
          for (ip in f) { if (f[ip] < fip && users[ip] < fus) continue; if (mx[ip] >= rate || users[ip] >= fus) { split(ip, o, "."); netm[o[1] "." o[2] "." o[3]]++ } }
          for (ip in f) { if (f[ip] < fip && users[ip] < fus && days[ip] < sld) continue
            mach = (mx[ip] >= rate || users[ip] >= fus) ? 1 : 0
            split(ip, o, "."); nm = netm[o[1] "." o[2] "." o[3]]+0; bynet = (!mach && nm >= 2) ? 1 : 0; if (bynet) mach = 1
            burst = (!mach && users[ip] == 1 && mx[ip] >= 3 && last[ip]-first[ip] <= 600) ? 1 : 0
            sleeper = (!mach && users[ip] >= 2 && (days[ip] >= sld || last[ip]-first[ip] >= sld*86400)) ? 1 : 0   # Tage mit Versuchen oder Spanne zwischen erstem und letztem Versuch
            v = (mach && okA[ip]>0) ? "TREFFER" : (mach ? (bynet ? "MASCHINE_NETZ" : "MASCHINE") : (okA[ip]>0 ? "NUTZER" : (sleeper ? "SCHLAEFER" : (burst ? "UNKLAR_BURST" : "UNKLAR"))))
            printf "%s\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%s\t%s\t%d\n", ip, f[ip], users[ip], first[ip], last[ip], mx[ip], okA[ip]+0, v, ul[ip], okL[ip], days[ip] }
          for (u in uf) printf "USER\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%s\n", u, uf[u], (u in okU) ? 1 : 0, uips[u], ufirst[u], ulast[u], umx[u], (u in uokAny) ? 1 : 0, uipl[u], uokIp[u] > "/dev/stderr" }' "$WORK/aaa.tsv" 2>"$WORK/aaa_users.txt" | sort -t"$(printf '\t')" -k2,2 -rn > "$WORK/aaa_ip.txt"
      # Adressen, die nur ein Brute-Force-Konto bearbeitet haben, gehoeren zum Brute-Force-Befund, nicht zum Spraying
      { echo "__keins__"; awk -F'\t' -v bf="${AAA_BF_MIN:-20}" -v rate="${AAA_RATE:-10}" '$3 >= bf || $8 >= rate { print $2 }' "$WORK/aaa_users.txt"; } > "$WORK/aaa_bfusers.txt"   # Platzhalterzeile: leere erste Datei bricht NR==FNR
      awk -F'\t' 'NR==FNR { b[$1]=1; next } !($3==1 && ($9 in b))' "$WORK/aaa_bfusers.txt" "$WORK/aaa_ip.txt" > "$WORK/aaa_ip2.txt" && mv "$WORK/aaa_ip2.txt" "$WORK/aaa_ip.txt"
      # eigene Adressen heraus (eigener Befund); Schlaefer auch ueber die kumulierte Liste (tage >= AAA_SLEEPER_DAYS)
      : > "$WORK/aaa_own.txt"; : > "$WORK/aaa_ip2.txt"
      _cumsl="$(dirname "${OUTFILE:-.}")/ns_quickcheck_observed_ips.tsv"
      while IFS="$(printf '\t')" read -r _ip _rest; do
        [ -n "$_ip" ] || continue
        if is_trusted_ip "$_ip"; then ip_note "aaa_$(echo "$_rest" | cut -f7 | tr 'A-Z' 'a-z')" "$_ip" "$(echo "$_rest" | cut -f1)" "$(msg ADDR_SRC_AAA_FAIL_TRUSTED)"; continue; fi
        if is_internal_ip "$_ip" || [ -n "$(own_obj "$_ip")" ]; then printf '%s\t%s\n' "$_ip" "$_rest" >> "$WORK/aaa_own.txt"; continue; fi
        _v=$(echo "$_rest" | cut -f7); _u=$(echo "$_rest" | cut -f2)
        if [ "$_v" = UNKLAR ] && [ "$_u" -ge 2 ] && [ -f "$_cumsl" ]; then _td=$(grep -v '^#' "$_cumsl" | awk -F'\t' -v i="$_ip" '$2==i && NF>=11 { if ($7>m) m=$7 } END { print m+0 }'); [ "$_td" -ge "${AAA_SLEEPER_DAYS:-2}" ] && _rest=$(echo "$_rest" | awk -F'\t' -v OFS='\t' -v d="$_td" '{ $7="SCHLAEFER"; $10=d; print }'); fi
        printf '%s\t%s\n' "$_ip" "$_rest" >> "$WORK/aaa_ip2.txt"
      done < "$WORK/aaa_ip.txt"; mv "$WORK/aaa_ip2.txt" "$WORK/aaa_ip.txt"
      NOWN=$(grep -c . "$WORK/aaa_own.txt"); NSLP=$(awk -F'\t' '$8=="SCHLAEFER"' "$WORK/aaa_ip.txt" | grep -c .)
      NIP=$(grep -c . "$WORK/aaa_ip.txt"); NHIT=$(awk -F'\t' '$8=="TREFFER"' "$WORK/aaa_ip.txt" | grep -c .); NMACH=$(awk -F'\t' '$8 ~ /^MASCHINE/' "$WORK/aaa_ip.txt" | grep -c .)
      # Kontonamen in die Zuordnungstabelle (anon-Fassung maskiert sie)
      cut -f2 "$WORK/aaa_users.txt" | grep -v '^$' | sort -u | while IFS= read -r _u; do anon_add user "$_u"; done
      # Brute Force auf einzelne Konten: viele Versuche auf ein Konto (AAA_BF_MIN) oder AAA_RATE/min auf ein Konto, von beliebig vielen Adressen
      # aaa_users.txt: USER, konto, fehl, erfolg-gleiche-adresse, adressen, erster, letzter, max/min, erfolg-danach-beliebig, adressliste, erfolgsadresse
      awk -F'\t' -v bf="${AAA_BF_MIN:-20}" -v rate="${AAA_RATE:-10}" '$3 >= bf || $8 >= rate' "$WORK/aaa_users.txt" | sort -t"$(printf '\t')" -k3,3 -rn > "$WORK/aaa_bf0.txt"
      : > "$WORK/aaa_bf.txt"
      while IFS="$(printf '\t')" read -r _l; do _ips=$(echo "$_l" | cut -f10 | tr ',' ' '); _alltr=1; for _ip in $_ips; do is_trusted_ip "$_ip" || _alltr=0; done
        if [ "$_alltr" -eq 1 ] && [ -n "$_ips" ]; then for _ip in $_ips; do ip_note aaa_bruteforce "$_ip" "$(echo "$_l" | cut -f3)" "$(msg ADDR_SRC_AAA_BF_TRUSTED)"; done; else printf '%s\n' "$_l" >> "$WORK/aaa_bf.txt"; fi; done < "$WORK/aaa_bf0.txt"
      NBF=$(grep -c . "$WORK/aaa_bf.txt"); NBFHIT=$(awk -F'\t' '$9==1' "$WORK/aaa_bf.txt" | grep -c .)
      if [ "$NBFHIT" -gt 0 ]; then TRACES=1; COMPROMISE=1; flag_red "$(msg AAA_BF_HIT_RED "$NBFHIT")"
        awk -F'\t' -v mr="$(msg_raw AAA_BF_HIT_ROW)" 'function m(t,a,b,c,d,e,f,g,h,i) { gsub(/%1/,a,t); gsub(/%2/,b,t); gsub(/%3/,c,t); gsub(/%4/,d,t); gsub(/%5/,e,t); gsub(/%6/,f,t); gsub(/%7/,g,t); gsub(/%8/,h,t); gsub(/%9/,i,t); return t } $9==1 { print m(mr, $2, $3, $5, $11) }' "$WORK/aaa_bf.txt" | LINE_MAX=0 show 10 1
        out "          | $(msg AAA_BF_HIT_TODO_DET)" 1; fi
      if [ "$NBF" -gt "$NBFHIT" ]; then flag_yel "$(msg AAA_BF_YEL "$((NBF - NBFHIT))")"
        awk -F'\t' -v mr="$(msg_raw AAA_BF_ROW)" -v mm="$(msg_raw AAA_BF_MORE_ROW)" 'function m(t,a,b,c,d,e,f,g,h,i) { gsub(/%1/,a,t); gsub(/%2/,b,t); gsub(/%3/,c,t); gsub(/%4/,d,t); gsub(/%5/,e,t); gsub(/%6/,f,t); gsub(/%7/,g,t); gsub(/%8/,h,t); gsub(/%9/,i,t); return t } $9!=1 && n<10 { n++; split($10, a, ","); ex=a[1]; for (i=2;i<=3 && i in a;i++) ex=ex ", " a[i]; if ($5>3) ex=ex ", +" ($5-3)
            cmd="perl -MPOSIX -e \"print strftime(q(%d.%m. %H:%M), localtime(" $6 "))\""; cmd | getline t1; close(cmd); cmd="perl -MPOSIX -e \"print strftime(q(%d.%m. %H:%M), localtime(" $7 "))\""; cmd | getline t2; close(cmd)
            print m(mr, sprintf("%-14s", $2), sprintf("%4d", $3), sprintf("%2d", $5), ex, t1, t2, $8) }
          END { if (NR>10) print m(mm, NR-10) }' "$WORK/aaa_bf.txt" | LINE_MAX=0 show 11 1
        awk -F'\t' '$9!=1 { print $10 }' "$WORK/aaa_bf.txt" | tr ',' '\n' | sort -u | while read -r _ip; do [ -n "$_ip" ] && ip_note aaa_bruteforce "$_ip" 1 "$(msg ADDR_SRC_AAA_BF)"; done
        out "          | $(msg AAA_BF_RESULT_DET)" 1
        out "          | $(msg AAA_BF_TODO_DET)" 1; fi
      if [ "$NHIT" -gt 0 ]; then TRACES=1; COMPROMISE=1; flag_red "$(msg AAA_HIT_RED "$NHIT")"
        awk -F'\t' -v mr="$(msg_raw AAA_HIT_ROW)" 'function m(t,a,b,c,d,e,f,g,h,i) { gsub(/%1/,a,t); gsub(/%2/,b,t); gsub(/%3/,c,t); gsub(/%4/,d,t); gsub(/%5/,e,t); gsub(/%6/,f,t); gsub(/%7/,g,t); gsub(/%8/,h,t); gsub(/%9/,i,t); return t } $8=="TREFFER" { print m(mr, $1, $2, $3, $10) }' "$WORK/aaa_ip.txt" | show 10 1
        awk -F'\t' '$8=="TREFFER" {print $1}' "$WORK/aaa_ip.txt" | while read -r _ip; do ip_note aaa_hit "$_ip" 1 "$(msg ADDR_SRC_AAA_HIT)"; done
        out "          | $(msg AAA_HIT_TODO_DET)" 1; fi
      if [ "$NSLP" -gt 0 ]; then flag_yel "$(msg AAA_SLEEPER_YEL "$NSLP")"
        awk -F'\t' -v mr="$(msg_raw AAA_SLEEPER_ROW)" 'function m(t,a,b,c,d,e,f,g,h,i) { gsub(/%1/,a,t); gsub(/%2/,b,t); gsub(/%3/,c,t); gsub(/%4/,d,t); gsub(/%5/,e,t); gsub(/%6/,f,t); gsub(/%7/,g,t); gsub(/%8/,h,t); gsub(/%9/,i,t); return t } $8=="SCHLAEFER" { split($9, a, ","); ex=a[1]; for (i=2;i<=5 && i in a;i++) ex=ex ", " a[i]; if ($3>5) ex=ex ", +" ($3-5)
            cmd="perl -MPOSIX -e \"print strftime(q(%d.%m.), localtime(" $4 "))\""; cmd | getline t1; close(cmd); cmd="perl -MPOSIX -e \"print strftime(q(%d.%m.), localtime(" $5 "))\""; cmd | getline t2; close(cmd)
            sp=int(($5-$4)/86400)+1; print m(mr, sprintf("%-16s", $1), sprintf("%4d", $2), sprintf("%3d", $3), $11, sp, t1, t2, $6, ex) }' "$WORK/aaa_ip.txt" | LINE_MAX=0 show 10 1
        awk -F'\t' '$8=="SCHLAEFER" {print $1 "\t" $2}' "$WORK/aaa_ip.txt" | while IFS="$(printf '\t')" read -r _ip _n; do ip_note aaa_sleeper "$_ip" "$_n" "$(msg ADDR_SRC_AAA_SLEEPER)"; done
        out "          | $(msg AAA_SLEEPER_RESULT_DET)" 1
        out "          | $(msg AAA_SLEEPER_TODO_DET)" 1; fi
      if [ "$NIP" -gt "$((NHIT + NSLP))" ]; then
        flag_yel "$(msg AAA_SPRAY_YEL "$NAF" "$NIP" "$NMACH")"
        [ "$NIP" -gt 1 ] && out "          | $(msg TRACE_NETS_DET "$(awk -F'\t' '$8!="NUTZER" { print $2, $1 }' "$WORK/aaa_ip.txt" | net24_summary)")" 1
        NNUT=$(awk -F'\t' '$8=="NUTZER"' "$WORK/aaa_ip.txt" | grep -c .); NUNK=$(awk -F'\t' '$8 ~ /^UNKLAR/' "$WORK/aaa_ip.txt" | grep -c .)
        out "$(msg AAA_SPRAY_SPLIT_DET "          | $NUNK" "$NMACH" "$NNUT")" 1
        { awk -F'\t' '$8 ~ /^UNKLAR/' "$WORK/aaa_ip.txt" | head -10; awk -F'\t' '$8 ~ /^MASCHINE/' "$WORK/aaa_ip.txt" | head -10; } | awk -F'\t' -v mx=20 -v mr="$(msg_raw AAA_SPRAY_ROW)" -v rm="$(msg AAA_RATE_MACHINE)" -v rmn="$(msg AAA_RATE_MACHINE_NET)" -v ru="$(msg AAA_RATE_USER)" -v rub="$(msg AAA_RATE_UNCLEAR_BURST)" -v ruc="$(msg AAA_RATE_UNCLEAR)" -v yes="$(msg TRACE_YES)" -v no="$(msg TRACE_NO)" 'function m(t,a,b,c,d,e,f,g,h,i) { gsub(/%1/,a,t); gsub(/%2/,b,t); gsub(/%3/,c,t); gsub(/%4/,d,t); gsub(/%5/,e,t); gsub(/%6/,f,t); gsub(/%7/,g,t); gsub(/%8/,h,t); gsub(/%9/,i,t); return t } $8!="TREFFER" && n<mx { n++; split($9, a, ","); ex=a[1]; for (i=2;i<=5 && i in a;i++) ex=ex ", " a[i]; if ($3>5) ex=ex ", +" ($3-5)
            cmd="perl -MPOSIX -e \"print strftime(q(%d.%m. %H:%M), localtime(" $4 "))\""; cmd | getline t1; close(cmd); cmd="perl -MPOSIX -e \"print strftime(q(%d.%m. %H:%M), localtime(" $5 "))\""; cmd | getline t2; close(cmd)
            v = ($8=="MASCHINE") ? rm : (($8=="MASCHINE_NETZ") ? rmn : (($8=="NUTZER") ? ru : (($8=="UNKLAR_BURST") ? rub : ruc)))
            print m(mr, sprintf("%-16s", $1), sprintf("%4d", $2), sprintf("%3d", $3), t1, t2, $6, ($7>0 ? yes : no), v, ex) }
          END { }' | LINE_MAX=0 show 20 1
        [ "$((NUNK + NMACH))" -gt 20 ] && out "          | $(msg AAA_SPRAY_MORE_DET "$((NUNK + NMACH - 20))")" 1
        awk -F'\t' '$8 ~ /^MASCHINE/ {print $1 "\t" $2}' "$WORK/aaa_ip.txt" | while IFS="$(printf '\t')" read -r _ip _n; do ip_note aaa_bruteforce "$_ip" "$_n" "$(msg ADDR_SRC_AAA_MACHINE)"; done
        out "          | $(msg AAA_TOP_ACCOUNTS_DET "$(sort -t"$(printf '\t')" -k3,3 -rn "$WORK/aaa_users.txt" | head -8 | awk -F'\t' -v sf="$(msg AAA_TOP_ACCOUNT_SUCCESS_FRAG)" '{ printf "%s (%d%s) ", $2, $3, ($4==1 ? sf : "") }')")" 1
        out "$(msg AAA_ACCOUNTS_TOTAL_DET "          | $(cut -f2 "$WORK/aaa_users.txt" | grep -vc '^$')" "$(awk -F'\t' '$3==1' "$WORK/aaa_users.txt" | grep -c .)")" 1
        out "          | $(msg TRACE_LOG_DET "$(log_hits "$AAA_FAIL_RE" $NSLOGS)")" 1
        out "          | $(msg AAA_SPRAY_RESULT_DET "${AAA_RATE:-10}" "${AAA_FAIL_USERS:-10}" "${AAA_OK_WIN:-5}")" 1
        out "          | $(msg AAA_SPRAY_TODO_DET)" 1
      elif [ "$NIP" -eq 0 ] && [ "$NOWN" -eq 0 ]; then inf "$(msg AAA_BELOW_THRESHOLD "$NAF" "${AAA_FAIL_IP:-5}" "${AAA_FAIL_USERS:-10}")" 1; fi
      if [ "$NOWN" -gt 0 ]; then
        NOWNHIT=$(awk -F'\t' '$8=="TREFFER"' "$WORK/aaa_own.txt" | grep -c .)
        [ "$NOWNHIT" -gt 0 ] && { TRACES=1; COMPROMISE=1; flag_red "$(msg AAA_OWN_HIT_RED "$NOWNHIT")"; awk -F'\t' -v mr="$(msg_raw AAA_HIT_ROW)" 'function m(t,a,b,c,d,e,f,g,h,i) { gsub(/%1/,a,t); gsub(/%2/,b,t); gsub(/%3/,c,t); gsub(/%4/,d,t); gsub(/%5/,e,t); gsub(/%6/,f,t); gsub(/%7/,g,t); gsub(/%8/,h,t); gsub(/%9/,i,t); return t } $8=="TREFFER" { print m(mr, $1, $2, $3, $10) }' "$WORK/aaa_own.txt" | show 5 1; }
        flag_yel "$(msg AAA_OWN_YEL "$NOWN")"
        awk -F'\t' '$8!="TREFFER" { print }' "$WORK/aaa_own.txt" | while IFS="$(printf '\t')" read -r _ip _f _u _t1 _t2 _mx _ok _v _ul _rest; do
          _o=$(own_obj "$_ip"); [ -n "$_o" ] && _o=" (ns.conf: $_o)" || _o="$(msg AAA_OWN_INTERNAL_FRAG)"
          _ex=$(echo "$_ul" | tr ',' '\n' | head -5 | tr '\n' ',' | sed 's/,$//; s/,/, /g')
          printf '%s\n' "$(msg AAA_OWN_ROW "$_ip" "$_o" "$_f" "$_u" "$(fmtdate "$_t1")" "$(fmtdate "$_t2")" "$_mx" "$( [ "$_ok" -gt 0 ] && msg TRACE_YES || msg TRACE_NO )" "$_ex")"; done | LINE_MAX=0 show 10 1
        out "          | $(msg AAA_OWN_RESULT_DET)" 1
        out "          | $(msg AAA_OWN_TODO_DET)" 1
      fi
    else grn "$(msg AAA_NONE_OK)"; fi
  fi
fi

# =============================================================================
# Vertraute Adressen: gesammelte Ausgabe, ohne Verdict-Wirkung (TRUST_LEVEL=yellow: als Gelb)
if [ -s "$TRUST_EVENTS" ]; then
  _cumt="$(dirname "${OUTFILE:-.}")/ns_quickcheck_observed_ips.tsv"
  cut -f1 "$TRUST_EVENTS" | sort -u | while read -r _tip; do
    _ti=$(trusted_info "$_tip"); _tb=$(echo "$_ti" | cut -d'|' -f2); _tm=$(echo "$_ti" | cut -d'|' -f1)
    if [ -f "$_cumt" ] && grep -v '^#' "$_cumt" | awk -F'\t' -v i="$_tip" '$2==i && $1 !~ /^trusted_/ { f=1 } END { exit f ? 0 : 1 }'; then
      _pc=$(grep -v '^#' "$_cumt" | awk -F'\t' -v i="$_tip" '$2==i && $1 !~ /^trusted_/ { print $1 }' | sort -u | tr '\n' ',' | sed 's/,$//')
      flag_yel "$(msg TRUST_LISTED_BEFORE_YEL "$_tip" "$_pc")"; fi
      flag_tru "$(msg TRUST_ACTIVE_TRU "$_tip" "$( if [ -n "$_tb" ]; then msg TRUST_UNTIL_PAREN_FRAG "$_tb"; else msg TRUST_UNLIMITED_PAREN_FRAG; fi )" "${_tm:-$(msg TRUST_NOTE_NONE)}")"
    grep "^$_tip	" "$TRUST_EVENTS" | cut -f2 | sort | uniq -c | awk '{ c=$1; $1=""; sub(/^ /,""); print $0 (c>1 ? "  (" c "x)" : "") }' | show 10 1
    out "          | $(msg TRUST_CHECK_DET)" 1
  done
  # Zaehler ausserhalb der Subshell (die Schleife laeuft in einer Pipe)
  TRUST_COUNT=$(cut -f1 "$TRUST_EVENTS" | sort -u | grep -c .)
  if [ "${TRUST_LEVEL:-trust}" = yellow ]; then YEL_COUNT=$((YEL_COUNT + TRUST_COUNT)); fi
  [ -f "$_cumt" ] && YEL_COUNT=$((YEL_COUNT + $(cut -f1 "$TRUST_EVENTS" | sort -u | while read -r _tip; do grep -v '^#' "$_cumt" | awk -F'\t' -v i="$_tip" '$2==i && $1 !~ /^trusted_/ { f=1 } END { exit f ? 0 : 1 }' && echo x; done | grep -c x) ))
fi
hdr "$(msg HDR_BLOCK5)"
# =============================================================================
for p in $PAYLOAD_PATHS; do
  [ -e "$ROOT/$p" ] || continue
  echo "/$p" | filter_wl "$WL_PATH" | grep -q . || continue
  case "$p" in var/tmp/.host) head -c 4 "$ROOT/$p" 2>/dev/null | grep -q 'ELF' || { flag_yel "$(msg CHECK_HOSTFILE_NOT_ELF_YEL "$p")"; continue; } ;; esac
  _md=$(fmtdate "$(mtime_of "$ROOT/$p")"); flag_red "$(msg CHECK_PAYLOAD_PATH_RED "$p" "$_md" "$(ioc_src path "$p")")"; COMPROMISE=1
done
WD=""; for d in $WEB_DIRS; do [ -d "$ROOT/$d" ] && WD="$WD $ROOT/$d"; done
if [ -n "$WD" ]; then
  WS=$(find $WD -type f \( -name '.ctxs*' -o -name '*.receiver' -o -name '*.receiver.*' -o -name '.slap*' -o -name '.local_journal*' \) 2>/dev/null | filter_wl "$WL_PATH")
  [ -n "$WS" ] && { flag_red "$(msg CHECK_WEBSHELL_NAMES_RED)"; echo "$WS" | show 10 1; COMPROMISE=1; }
  PHP=$(find $WD -type f -name '*.php' ! -path '*/admin_ui/*' ! -path '*/websocketd/*' ! -path '*/ns_gui/*' 2>/dev/null | filter_wl "$WL_PATH" | head -20)
  [ -n "$PHP" ] && { flag_red "$(msg CHECK_PHP_OUTSIDE_RED)"; echo "$PHP" | show 10 1; COMPROMISE=1; }
  # Upgrade-Zeitpunkt aus nsinstall.log: Dateien bis 30 min nach dem letzten Upgrade gelten als Upgrade-Aenderung
  UPG=""; _nsi="$ROOT/var/log/nsinstall.log"; [ -f "$_nsi" ] || _nsi="$ROOT/var/nsinstall/nsinstall.log"
  if [ -f "$_nsi" ]; then UPG=$(mtime_of "$_nsi"); [ -n "$UPG" ] && inf "$(msg CHECK_LAST_UPGRADE "$(fmtdate "$UPG")")" 1; fi
  if [ -n "$BOOT" ]; then
    # Liste "mtime<TAB>pfad" der seit Boot (plus 15 min) geaenderten Web-Dateien, ohne das Upgrade-Fenster (nsinstall.log plus 30 min)
    if [ -n "$MANIFEST" ] && [ -f "$MANIFEST" ]; then
      awk -F'\t' -v b="$BOOT" -v u="${UPG:-0}" -v dirs="$(echo $WEB_DIRS | sed 's/ /|/g')" 'NR>1 && $2=="f" && ($7+0) > (b+900) && !(u>0 && ($7+0) >= u-60 && ($7+0) <= u+1800) && $1 ~ "^/(" dirs ")/" {print $7"\t"$1}' "$MANIFEST" > "$WORK/neww.txt"
    else
      AGE=$(( (NOW - BOOT) / 60 - 15 )); [ "$AGE" -gt 0 ] || AGE=1
      find $WD -type f -mmin -"$AGE" 2>/dev/null | UPG="${UPG:-0}" perl -ne 'chomp; @s=stat($_); next unless @s; next if $ENV{UPG}>0 && $s[9] >= $ENV{UPG}-60 && $s[9] <= $ENV{UPG}+1800; print "$s[9]\t$_\n"' > "$WORK/neww.txt"
    fi
    # Whitelist anwenden: Verzeichnisregeln (enden mit /) decken keinen Code ab; Dateiregeln auf Code gelten nur mit Pin
    CODE_RE='\.(js|php|pl|sh|cgi|py)$|/plugins\.xml$'
    WL_WEB_NOCODE=$(printf '%s' "$WL_WEBFILE" | tr '|' '\n' | grep -viE '\\?\.(js|php|pl|sh|cgi|py)\$$|plugins\\?\.xml\$$' | tr '\n' '|' | sed 's/|$//')
    awk -F'\t' '{print $2}' "$WORK/neww.txt" | { grep -viE "$CODE_RE" | filter_wl "$WL_WEBFILE"; awk -F'\t' '{print $2}' "$WORK/neww.txt" | grep -iE "$CODE_RE" | awk -v pins="$WL_WEBPIN" 'BEGIN { while ((getline l < pins) > 0) { split(l, f, "\t"); re[++n]=f[1] } } { keep=1; for (i=1;i<=n;i++) if ($0 ~ re[i]) keep=0; if (keep) print }'; } | sort -u > "$WORK/neww_paths.txt"
    # Hash-Pins: freigegebene Datei mit anderem Hash ist wieder ein Befund
    if [ -s "$WL_WEBPIN" ]; then
      awk -F'\t' '{print $2}' "$WORK/neww.txt" | while IFS= read -r _wp; do
        while IFS="$(printf '\t')" read -r _re _h; do
          if echo "$_wp" | grep -qE "$_re"; then _f="$ROOT$_wp"; [ -f "$_f" ] || continue; _hh=$(sha256 -q "$_f" 2>/dev/null || sha256sum "$_f" 2>/dev/null | cut -c1-64)
            [ "$_hh" = "$_h" ] || { echo "$_wp"; printf '%s\t%s\n' "$_wp" "$_hh" >> "$WORK/wl_pinfail.txt"; }; fi; done < "$WL_WEBPIN"; done | sort -u >> "$WORK/neww_paths.txt"
      sort -u "$WORK/neww_paths.txt" -o "$WORK/neww_paths.txt"
      [ -s "$WORK/wl_pinfail.txt" ] && flag_yel "$(msg CHECK_PIN_MISMATCH_YEL "$(grep -c . "$WORK/wl_pinfail.txt")")" && cut -f1 "$WORK/wl_pinfail.txt" | show 5 1
    fi
    NNEW=$(grep -c . "$WORK/neww_paths.txt")
    if [ "$NNEW" -gt 0 ]; then
      # Burst-Regel: liegen alle Aenderungen innerhalb von 30 s, ist es ein Rewrite (Theme, Upgrade-Nachlauf)
      grep -F -f "$WORK/neww_paths.txt" "$WORK/neww.txt" | awk -F'\t' 'NR==1{mn=$1;mx=$1} {if($1<mn)mn=$1; if($1>mx)mx=$1} END{print mn"\t"mx}' > "$WORK/neww_span.txt"
      MN=$(cut -f1 "$WORK/neww_span.txt"); MX=$(cut -f2 "$WORK/neww_span.txt")
      if [ "$NNEW" -ge 5 ] && [ -n "$MN" ] && [ $((MX - MN)) -le 30 ]; then
        inf "$(msg CHECK_WEB_BURST "$NNEW" "$(fmtdate "$MN")" "$((MX - MN))")" 1
        head -3 "$WORK/neww_paths.txt" | show 3
      else
        if [ "$NNEW" -ge 20 ]; then flag_yel "$(msg CHECK_WEB_MANY_YEL "$NNEW" "$(( (MX - MN) / 60 ))")"
        else flag_yel "$(msg CHECK_WEB_FEW_YEL "$NNEW")"; fi
        # alle nicht freigegebenen Dateien mit Aenderungszeit, neueste zuerst; ab 20 je Verzeichnis gruppiert (Code bleibt einzeln)
        grep -F -f "$WORK/neww_paths.txt" "$WORK/neww.txt" | sort -rn | CODE_RE="$CODE_RE" MSG_GROUP="$(msg_raw CHECK_WEB_DIR_GROUP_ROW)" perl -MPOSIX -e '
          my (@l,%n,%mn,%mx,%done); my $code=$ENV{CODE_RE};
          while (<STDIN>) { chomp; my ($t,$p)=split /\t/; next unless defined $p; (my $d=$p) =~ s{/[^/]*$}{}; $n{$d}++; $mn{$d}=$t if !defined $mn{$d} || $t<$mn{$d}; $mx{$d}=$t if !defined $mx{$d} || $t>$mx{$d}; push @l,[$t,$p,$d,($p =~ /$code/i ? 1 : 0)] }
          for my $e (@l) { my ($t,$p,$d,$c)=@$e;
            if ($n{$d} >= 20 && !$c) { next if $done{$d}++; my $g=$ENV{MSG_GROUP}; my @v=($d, $n{$d}, strftime("%Y-%m-%d %H:%M", localtime $mn{$d}), strftime("%Y-%m-%d %H:%M", localtime $mx{$d})); for my $i (1..4) { $g =~ s/%$i/$v[$i-1]/ } printf "%d\t%s\n", $mx{$d}, $g }
            else { printf "%d\t%s  %s\n", $t, strftime("%Y-%m-%d %H:%M", localtime $t), $p } }' 2>/dev/null | sort -rn | cut -f2- > "$WORK/neww_show.txt"
        [ -s "$WORK/neww_show.txt" ] || awk -F'\t' '{ print $2 }' "$WORK/neww.txt" | grep -F -f "$WORK/neww_paths.txt" > "$WORK/neww_show.txt"
        # alle Zeilen in Report und Terminal (DETAIL_MAX in der Config begrenzt die Anzeige, der Report bleibt vollstaendig)
        show 0 1 < "$WORK/neww_show.txt"
        _wfirst=$(grep -F -f "$WORK/neww_paths.txt" "$WORK/neww.txt" | cut -f1 | sort -n | head -1); _wlast=$(grep -F -f "$WORK/neww_paths.txt" "$WORK/neww.txt" | cut -f1 | sort -n | tail -1)
        # Einordnung ueber ALLE geaenderten Dateien, nicht nur die angezeigten
        _wout=$(grep -vcE '^/var/netscaler/logon/themes/|favicon\.ico$|/images/' "$WORK/neww_paths.txt"); _wphp=$(grep -ciE '\.php$' "$WORK/neww_paths.txt")
        _wexec=$(grep -iE '\.(js|php|pl|sh|cgi|py)$|/plugins\.xml$' "$WORK/neww_paths.txt" | grep -vciE '\.php$'); _wexecl=$(grep -iE '\.(js|pl|sh|cgi|py)$|/plugins\.xml$' "$WORK/neww_paths.txt" | head -5)
        out "          | $(msg CHECK_WEB_WHEN_DET "$( [ -n "$_wfirst" ] && fmtdate "$_wfirst" || echo ?)" "$( [ -n "$_wlast" ] && fmtdate "$_wlast" || echo ?)" "$(fmtdate "$BOOT")")" 1
        if [ "${_wphp:-0}" -gt 0 ] && [ "${PHP_ANOM:-0}" -ge "${PHP_ANOMALY_MIN:-3}" ] && [ "$VULN63" -eq 1 ]; then TRACES=1; COMPROMISE=1; flag_red "$(msg CHECK_PHP2SHELL_RED)"; out "          | $(msg CHECK_PHP2SHELL_TODO_DET)" 1; fi
        if [ "${_wphp:-0}" -gt 0 ]; then out "          | $(msg CHECK_WEB_RESULT_PHP_DET "$_wphp")" 1
        elif [ "${_wout:-0}" -gt 0 ]; then out "          | $(msg CHECK_WEB_RESULT_OUTSIDE_DET "$_wout")" 1
        elif [ "${_wexec:-0}" -gt 0 ]; then out "          | $(msg CHECK_WEB_RESULT_EXEC_DET "$_wexec")" 1
        else out "          | $(msg CHECK_WEB_RESULT_THEME_DET)" 1; fi
        if [ "${_wexec:-0}" -gt 0 ]; then out "          | $(msg CHECK_WEB_CODE_DET)" 1; grep -iE "$CODE_RE" "$WORK/neww_paths.txt" | head -5 | show 5 1; fi
        out "          | $(msg CHECK_WEB_TODO1_DET)" 1
        out "          | $(msg CHECK_WEB_TODO2_DET)" 1
        [ "${_wphp:-0}" -gt 0 ] || [ "${_wout:-0}" -gt 0 ] && out "          | $(msg CHECK_WEB_TODO3_DET)" 1
      fi
    else grn "$(msg CHECK_WEB_NONE_OK)"; fi
  fi
fi
if [ -f "$ETC_HTTPD" ] && [ -n "$BOOT" ]; then
  HM=$(mtime_of "$ETC_HTTPD"); HMOFF=0
  if [ -n "$HM" ] && { [ "$HM" -lt $((BOOT - 60)) ] || [ "$HM" -gt $((BOOT + 900)) ]; } && [ $((NOW - HM)) -lt 1209600 ]; then HMOFF=1; fi
  # Stock 14.1 hat AddType application/x-httpd-php (Admin-UI). Befund nur: Aliase in Gateway-Pfade,
  # PHP-Handler oder -Flags innerhalb von Directory/Location-Bloecken fuer logon, vpn, epa.
  HH=$(awk -v roots="$STOCK_ALIAS_ROOTS" 'BEGIN{IGNORECASE=1; inb=0}
       /^[[:space:]]*#/ {next}
       /<(Directory|Location|DirectoryMatch|LocationMatch)[^>]*(logon|\/vpns?|\/epa)/ {inb=1}
       /<\/(Directory|Location|DirectoryMatch|LocationMatch)>/ {inb=0}
       /(Alias|AliasMatch|ScriptAlias)[[:space:]]+\^?\/(vpns?|logon|epa)\// { tgt=$NF; gsub(/["'"'"']/, "", tgt); ok=0; n=split(roots, r, " "); for (i=1;i<=n;i++) if (index(tgt, r[i])==1) ok=1; if (!ok) print NR": "$0; next }
       inb && /(AddHandler|AddType|SetHandler).*php|php_flag|php_admin_value|php_value/ {print NR": "$0}' "$ETC_HTTPD" 2>/dev/null)
  if [ -n "$HH" ]; then
    [ "$HMOFF" = 1 ] && flag_red "$(msg CHECK_HTTPD_CHANGED_RED "$(fmtdate "$HM")")"
    [ "$HMOFF" = 1 ] || flag_red "$(msg CHECK_HTTPD_CONTENT_RED)"
    echo "$HH" | show 5 1; COMPROMISE=1
  elif [ "$HMOFF" = 1 ]; then
    flag_yel "$(msg CHECK_HTTPD_CHANGED_YEL "$(fmtdate "$HM")")"
    out "          | $(msg CHECK_HTTPD_WHAT_DET)" 1
    out "          | $(msg CHECK_HTTPD_HARMLESS_DET)" 1
  fi
fi
CRON=$(state_or crontab_root crontab -l | grep -vE "$ALLOWED_CRON_RE" | filter_wl "$WL_CRON")
[ -n "$CRON" ] && { flag_yel "$(msg CHECK_CRON_ROOT_YEL)"; echo "$CRON" | show 5 1
  if [ -n "$CRONLOGS" ]; then echo "$CRON" | awk '{ for (i=6;i<=NF;i++) printf "%s%s", $i, (i<NF ? " " : "\n") }' | while IFS= read -r _cmd; do _k=$(echo "$_cmd" | awk '{print $1}'); _last=$(catlogs $CRONLOGS | grep -aF -- "$_k" | tail -1 | cut -c1-15); out "$(msg CHECK_CRON_LASTRUN_DET "          | $_k" "${_last:-$(msg CHECK_CRON_NOT_IN_WINDOW)}")" 1; done; fi }
NOB=$(state_or crontab_nobody crontab -l -u nobody | grep -viE '^#|no crontab|^[[:space:]]*$' | grep -c .)
[ "${NOB:-0}" -gt 0 ] && { flag_red "$(msg CHECK_CRON_NOBODY_RED "$NOB")"; COMPROMISE=1; }
state_or sockstat_4l sockstat -4l | awk 'NR>1{print $2" "$1" "$6}' | grep -E "$SUSPECT_LISTENER_RE" | filter_wl "$WL_LISTENER" > "$WORK/ls_all.txt"
if [ -n "$KNOWN_LISTENER_RE" ]; then grep -vE "$KNOWN_LISTENER_RE" "$WORK/ls_all.txt" > "$WORK/ls_unk.txt"; else cp "$WORK/ls_all.txt" "$WORK/ls_unk.txt"; fi
LS_EXT=$(grep -vE ' 127\.0\.0\.1:[0-9]+$| \[?::1\]?:[0-9]+$' "$WORK/ls_unk.txt")
LS_LO=$(grep -E ' 127\.0\.0\.1:[0-9]+$| \[?::1\]?:[0-9]+$' "$WORK/ls_unk.txt")
[ -n "$LS_EXT" ] && { flag_red "$(msg CHECK_LISTENER_EXT_RED)"; echo "$LS_EXT" | show 5 1; COMPROMISE=1; }
[ -n "$LS_LO" ] && { flag_yel "$(msg CHECK_LISTENER_LO_YEL)"; echo "$LS_LO" | show 5 1; }
# verdaechtige Prozesse (SUSPECT_PROC_RE) mit Parent-Pruefung; Prozessliste online per ps, offline aus state/ps_lstart.txt
if [ -n "$SUSPECT_PROC_RE" ]; then
  state_or ps_lstart ps -axo pid,ppid,user,lstart,command > "$WORK/psall.txt"
  grep -aE "$SUSPECT_PROC_RE" "$WORK/psall.txt" | grep -av 'grep' > "$WORK/sp.txt"
  if [ -s "$WORK/sp.txt" ]; then
    while read -r _pid _ppid _rest; do
      _pc=$(awk -v p="$_ppid" '$1==p {for(i=9;i<=NF;i++) printf "%s ", $i; print ""; exit}' "$WORK/psall.txt")
      if [ -n "$SUSPECT_PROC_PARENT_OK_RE" ] && echo "$_pc" | grep -qE "$SUSPECT_PROC_PARENT_OK_RE"; then
        inf "$(msg CHECK_MONITOR_STOCK "$_pid" "$_pc")" 1
      else
        case "$_pc" in
          *cron*) flag_yel "$(msg CHECK_SUSPECT_PROC_CRON_YEL "$_pid" "$_ppid")" ;;
          *)      flag_red "$(msg CHECK_SUSPECT_PROC_RED "$_pid" "${_pc:-$(msg CHECK_UNKNOWN)}")"; COMPROMISE=1 ;;
        esac
        grep -aE "^[[:space:]]*$_pid[[:space:]]" "$WORK/psall.txt" | show 2 1
      fi
      # Kindprozesse des Monitor-Scripts: Shell oder Downloader = Ausfuehrung der Injection
      if [ -n "$SUSPECT_PROC_CHILD_RE" ]; then
        awk -v p="$_pid" '$2==p {for(i=9;i<=NF;i++) printf "%s ", $i; print ""}' "$WORK/psall.txt" | grep -aE "$SUSPECT_PROC_CHILD_RE" > "$WORK/spc.txt"
        if [ -s "$WORK/spc.txt" ]; then
          flag_red "$(msg CHECK_MONITOR_CHILD_RED "$_pid")"; COMPROMISE=1
          show 3 1 < "$WORK/spc.txt"
        fi
      fi
    done < "$WORK/sp.txt"
  fi
fi
# Hashes von Systemdateien (STOCK_HASH_FILES); Bewertung nur, wenn STOCK_FILE_HASHES einen Wert fuer Pfad und Build hat
for _hf in $STOCK_HASH_FILES; do
  _p="$ROOT/$_hf"; [ -f "$_p" ] || continue
  _h=$(sha256_of "$_p" 2>/dev/null); [ -n "$_h" ] || continue
  _exp=$(echo "$STOCK_FILE_HASHES" | tr ' ' '\n' | grep -E "^$_hf::[0-9a-f]{64}::$BUILD$" | cut -d: -f3)
  if [ -z "$_exp" ]; then inf "$(msg CHECK_HASH_NO_STOCK "$_hf" "$_h" "$BUILD")" 1
  elif [ "$_exp" = "$_h" ]; then grn "$(msg CHECK_HASH_STOCK_OK "$_hf" "$BUILD")"
  else flag_red "$(msg CHECK_HASH_MISMATCH_RED "$_hf" "$BUILD" "$_h")"; COMPROMISE=1; fi
done
# ausgehende Verbindungen gegen Payload-Hosts und bekannte Angreifer-Adressen
OUTRE=""; [ -n "$HOSTS" ] && OUTRE=$(echo "$HOSTS" | awk '{ v=$0; gsub(/\./, "\\.", v); if (v ~ /^[0-9\\.]+$/) v = "(^|[^0-9.])" v "([^0-9.]|$)"; s = s (s ? "|" : "") v } END { printf "%s", s }')
[ -n "$ATTACKER_IP_RE" ] && OUTRE="${OUTRE:+$OUTRE|}$ATTACKER_IP_RE"
[ -n "$ATTACKER_DOM_RE" ] && OUTRE="${OUTRE:+$OUTRE|}$ATTACKER_DOM_RE"
if [ -n "$OUTRE" ]; then
  state_or sockstat_4c sockstat -4c > "$WORK/conn.txt"; state_or netstat_an netstat -an >> "$WORK/conn.txt"
  OC=$(grep -aiE "$OUTRE" "$WORK/conn.txt" | sort -u)
  [ -n "$OC" ] && { flag_red "$(msg CHECK_OUTBOUND_RED)"; echo "$OC" | show 5 1; COMPROMISE=1
    echo "$OC" | grep -oE "$OUTRE" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u | while read -r _ip; do ip_note outbound_hit "$_ip" 1 "sockstat/netstat"; done; }
fi
ALLOWRE=$(echo "$ALLOWED_SYSTEM_USERS" | tr ' ' '\n' | grep -v '^$' | sed 's/.*/^&$/' | tr '\n' '|' | sed 's/|$//')
SU=$(grep -E '^add system user ' "$NSCONF" | awk '{print $4}' | tr -d '"' | grep -vx nsroot | grep -vxF -- "${CLI_USER:-nsroot}" | filter_wl "${ALLOWRE:+$ALLOWRE}${ALLOWRE:+${WL_USER:+|}}$WL_USER" | tr '\n' ' ' | sed 's/ $//')
[ -n "$SU" ] && flag_yel "$(msg CHECK_LOCAL_USERS_YEL "$SU")"
grep -E '^add system user ' "$NSCONF" | grep -qw sec_monitor && { flag_red "$(msg CHECK_SEC_MONITOR_RED)"; COMPROMISE=1; }
grep -qiE 'defaultEPAGroup[[:space:]]+"?NO_AUTH' "$NSCONF" && { flag_red "$(msg CHECK_EPA_NOAUTH_RED)"; COMPROMISE=1; }
SHP=$(state_or ls_bin_sh ls -lL /bin/sh | awk 'NR==1{print $1}')
case "$SHP" in *s*) flag_red "$(msg CHECK_SH_SETUID_RED "$SHP")"; COMPROMISE=1 ;; esac
# gespeicherte Aenderungen seit dem vorletzten Save: ns.conf.0 gegen ns.conf, nur sicherheitsrelevante Objekte
NSCONF0="$(dirname "$NSCONF")/ns.conf.0"
if [ -f "$NSCONF0" ]; then
  SECRE='^(add|rm|bind|unbind) system (user|group|cmdPolicy)|^(add|set|bind|unbind) authentication|^bind (vpn|authentication) vserver .* -policy|^(add|set) vpn (sessionAction|sessionPolicy|epaProfile)|^(add|set|bind) aaa |defaultEPAGroup|^(add|set) ns (ip|tcpParam)|^set ns param|^(add|bind) responder (policy|global)'
  norm_sec() { grep -E "$SECRE" | sed -E -e 's/ -devno [0-9]+//g' -e 's/ -(password|passwd|keyValue|secret|radKey|ldapBindDnPassword|sharedSecret) [^ ]+/ -\1 <secret>/g' -e 's/ -encrypted( -encryptmethod ENCMTHD_[0-9]+)?( -kek)?( -suffix [^ ]+)?//g' -e 's/(^| )[0-9a-fA-F]{48,}( |$)/\1<secret>\2/g' -e 's/[[:space:]]+/ /g' | sort -u; }
  norm_sec < "$NSCONF0" > "$WORK/sec0.txt"; norm_sec < "$NSCONF" > "$WORK/sec1.txt"
  diff "$WORK/sec0.txt" "$WORK/sec1.txt" 2>/dev/null | grep -E '^[<>]' > "$WORK/sd_all.txt"
  # Zeilen, die den Service-User dieses Verfahrens betreffen (Konto, Bindung, seine Command Policy), sind Info
  if [ -n "$CLI_USER" ]; then
    grep -E "system user $CLI_USER( |\$)|cmdPolicy cp_${CLI_USER}_ro( |\$)" "$WORK/sd_all.txt" > "$WORK/sd_svc.txt"
    grep -vE "system user $CLI_USER( |\$)|cmdPolicy cp_${CLI_USER}_ro( |\$)" "$WORK/sd_all.txt" > "$WORK/sd.txt"
  else : > "$WORK/sd_svc.txt"; cp "$WORK/sd_all.txt" "$WORK/sd.txt"; fi
  if [ -s "$WORK/sd_svc.txt" ]; then
    inf "$(msg CHECK_SVC_USER_CHANGED "$CLI_USER" "$(grep -c . "$WORK/sd_svc.txt")")" 1
  fi
  SD=$(cat "$WORK/sd.txt")
  NSD=$(echo "$SD" | grep -c .)
  if [ "$NSD" -gt 0 ]; then
    T0=$(fmtdate "$(mtime_of "$NSCONF0")"); T1=$(fmtdate "$(mtime_of "$NSCONF")")
    if echo "$SD" | grep -qE '^> (add|bind) system (user|group)|^< bind (vpn|authentication) vserver .* -policy|^< (add|set) vpn epaProfile|^> .*defaultEPAGroup.*NO_AUTH|^> add ns ip .* -mgmtAccess ENABLED'; then
      flag_red "$(msg CHECK_SAVED_DIFF_RED "$NSD" "$T0" "$T1")"; COMPROMISE=1
    else flag_yel "$(msg CHECK_SAVED_DIFF_YEL "$NSD" "$T0" "$T1")"; fi
    echo "$SD" | awk -v r="$(msg CHECK_DIFF_REMOVED)" -v a="$(msg CHECK_DIFF_ADDED)" '/^< / { print r " " substr($0,3); next } /^> / { print a " " substr($0,3); next } { print }' | show 8 1
  else grn "$(msg CHECK_SAVED_DIFF_NONE_OK)"; fi
fi
# ungespeicherte Config-Aenderungen (CLI-Ebene, Normalisierung wie ns_snapshot V5)
if [ "$CLI_MODE" != none ]; then
  norm_cfg() {
    grep -vE '^#|^[[:space:]]*$|^ Done$' \
    | sed -E -e 's/ -devno [0-9]+//g' \
             -e 's/ -(keyValue|password|passwd|secret|radKey|ldapBindDnPassword|sharedSecret|preSharedKey|authKey|privKey|encryptionKey|hashedPassword|kerberosPassword|radiusKey|tacacsKey) [^ ]+/ -\1 <secret>/g' \
             -e 's/ -passphrase [^ ]+/ -passphrase <secret>/g' \
             -e 's/ -inform [Pp][Ff][Xx]/ -inform PFX/g' -e 's/ -inform [Pp][Ee][Mm]/ -inform PEM/g' -e 's/ -inform [Dd][Ee][Rr]/ -inform DER/g' \
             -e 's/ -inform PFX ([^- ][^ ]*)/ -inform PFX <secret>/g' \
             -e 's/ -encrypted( -encryptmethod ENCMTHD_[0-9]+)?( -kek)?( -suffix [^ ]+)?//g' \
             -e 's/(^| )[0-9a-fA-F]{48,}( |$)/\1<secret>\2/g' \
             -e 's/[[:space:]]+/ /g' -e 's/[[:space:]]*$//' | sort -u; }
  cli "show ns runningConfig" > "$WORK/running.txt"
  if [ -s "$WORK/running.txt" ] && grep -q '^add \|^set \|^bind ' "$WORK/running.txt"; then
    norm_cfg < "$WORK/running.txt" > "$WORK/run.cfg"; norm_cfg < "$NSCONF" > "$WORK/saved.cfg"
    UD=$(diff "$WORK/saved.cfg" "$WORK/run.cfg" | grep -E '^[<>]'); NUD=$(echo "$UD" | grep -c .)
    if [ "$NUD" -gt 0 ]; then
      UNSAVED=1
      if echo "$UD" | grep -qE '^> (add|bind) system (user|group)|^> (set|add) authentication|^< bind (authentication|vpn) vserver|^> add (responder|vpn traffic)'; then
        flag_red "$(msg CHECK_UNSAVED_RED "$NUD")"; COMPROMISE=1
      else flag_yel "$(msg CHECK_UNSAVED_YEL "$NUD")"; fi
      echo "$UD" | awk -v r="$(msg CHECK_DIFF_SAVED_ONLY)" -v a="$(msg CHECK_DIFF_RUNNING_ONLY)" '/^< / { print r " " substr($0,3); next } /^> / { print a " " substr($0,3); next } { print }' | show 8 1
    else grn "$(msg CHECK_UNSAVED_NONE_OK)"; fi
  else inf "$(msg CHECK_RUNNING_EMPTY)" 1; fi
  AS=$(cli "show aaa session" | grep -aciE 'client ip|user')
  [ "${AS:-0}" -gt 0 ] && inf "$(msg CHECK_AAA_SESSIONS "$AS")" 1 && cli "show aaa session" | show 10
  SA=$(cli "show ns simpleacl" | grep -aciE 'simpleacl|ACL')
  [ "${SA:-0}" -gt 0 ] && inf "$(msg CHECK_SIMPLEACL "$SA")" 1
fi
# --compare: neue oder geaenderte Web-Dateien, neue User und Listener gegenueber einem Snapshot
if [ -n "$COMPARE" ]; then
  CDIR=""
  if [ "$COMPARE" = latest ] || [ "$COMPARE" = cron ]; then
    if [ "$COMPARE" = cron ]; then
      LAST=""; for ix in $(ls -t "$BASE_DIR"/out/*_index.txt 2>/dev/null); do
        if grep -q '^status=complete$' "$ix"; then LAST="${ix%_index.txt}_1-config.tgz"; [ -f "$LAST" ] && break; LAST=""; fi
      done
    else LAST=$(ls -t "$BASE_DIR"/out/*_1-config.tgz 2>/dev/null | head -1); fi
    if [ -n "$LAST" ]; then
      NEED=$(( $(wc -c < "$LAST" | tr -d ' ') / 1024 * 4 + 20480 )); FREE=$(free_kb "$WORK")
      if [ -n "$FREE" ] && [ "$FREE" -lt "$NEED" ]; then
        inf "$(msg CHECK_CMP_NO_SPACE "$COMPARE" "$WORK" "${FREE}" "${NEED}" "$(basename "$LAST")")" 1
      else
        mkdir -p "$WORK/cmp" && tar -xzf "$LAST" -C "$WORK/cmp" manifest state 2>"$WORK/tar.err" && CDIR="$WORK/cmp"
        [ -n "$CDIR" ] || { _te=$(head -1 "$WORK/tar.err" 2>/dev/null); inf "$(msg CHECK_CMP_EXTRACT_FAIL "$COMPARE" "$(basename "$LAST")" "$_te")" 1; }
      fi
    else inf "$(msg CHECK_CMP_NO_SET "$COMPARE" "$BASE_DIR")" 1; fi
  else CDIR="${COMPARE%/}"; fi
  if [ -n "$CDIR" ] && [ -f "$CDIR/manifest/files.tsv" ]; then
    CTS=$(awk -F'\t' '$1=="snapshot_ts"{print $2}' "$CDIR/manifest/meta.tsv" 2>/dev/null)
    inf "$(msg CHECK_CMP_AGAINST "${CTS:-$(msg CHECK_UNKNOWN)}" "$COMPARE")" 1
    if [ "$MODE" = online ] && [ -n "$WD" ]; then
      # aktuelle Web-Dateien mit mtime und Groesse gegen das alte Manifest
      find $WD -type f 2>/dev/null | perl -ne 'chomp; @s=stat($_); print "$_\t$s[9]\t$s[7]\n" if @s' | sort > "$WORK/cur.tsv"
      awk -F'\t' 'NR>1 && $2=="f" {print $1"\t"$7"\t"$3}' "$CDIR/manifest/files.tsv" | sort > "$WORK/old.tsv"
      join -t "$(printf '\t')" -a 1 -o 1.1,1.2,1.3,2.2,2.3 "$WORK/cur.tsv" "$WORK/old.tsv" 2>/dev/null \
           | awk -F'\t' '$4=="" {print "NEU\t"$1} $4!="" && ($2!=$4 || $3!=$5) {print "GEAENDERT\t"$1}' > "$WORK/ch_all.tsv"
      # Whitelist auf den reinen Pfad anwenden (verankerte Regeln ^/ und ...$ muessen passen), dann Status wieder dazu
      cut -f2 "$WORK/ch_all.tsv" | filter_wl "$WL_WEBFILE" > "$WORK/ch_keep.txt"
      CH=$(awk -F'\t' 'NR==FNR { k[$0]=1; next } ($2 in k)' "$WORK/ch_keep.txt" "$WORK/ch_all.tsv")
      NCH=$(echo "$CH" | grep -c .)
      if [ "$NCH" -gt 0 ]; then
        if [ "$NCH" -ge 20 ]; then flag_yel "$(msg CHECK_CMP_WEB_MANY_YEL "$NCH" "${CTS:-?}")"
        else flag_yel "$(msg CHECK_CMP_WEB_YEL "$NCH" "${CTS:-?}")"; fi
        echo "$CH" | awk -F'\t' -v n="$(msg CHECK_CMP_NEW)" -v c="$(msg CHECK_CMP_CHANGED)" '{ print ($1=="NEU" ? n : c) "\t" $2 }' | show 10 1
      else grn "$(msg CHECK_CMP_WEB_NONE_OK "${CTS:-?}")"; fi
    fi
    OU=$(grep -E '^add system user ' "$CDIR/state/system_users.txt" 2>/dev/null | awk '{print $4}' | tr -d '"' | sort -u)
    CU=$(grep -E '^add system user ' "$NSCONF" | awk '{print $4}' | tr -d '"' | sort -u)
    NU=$(for u in $CU; do echo "$OU" | grep -qx "$u" || echo "$u"; done)
    [ -n "$NU" ] && { flag_red "$(msg CHECK_CMP_NEW_USER_RED "${CTS:-?}" "$(echo $NU)")"; COMPROMISE=1; }
    if [ "$MODE" = online ] && [ -f "$CDIR/state/sockstat_4l.txt" ]; then
      sockstat -4l 2>/dev/null | awk 'NR>1{print $2" "$6}' | sort -u > "$WORK/lsnow.txt"
      awk 'NR>1{print $2" "$6}' "$CDIR/state/sockstat_4l.txt" | sort -u > "$WORK/lsold.txt"
      NL=$(while read -r l; do grep -qxF "$l" "$WORK/lsold.txt" || echo "$l"; done < "$WORK/lsnow.txt" | filter_wl "$WL_LISTENER")
      [ -n "$NL" ] && { flag_yel "$(msg CHECK_CMP_NEW_LISTENER_YEL "${CTS:-?}")"; echo "$NL" | show 5 1; }
    fi
  elif [ -n "$CDIR" ]; then inf "$(msg CHECK_CMP_NO_MANIFEST "$CDIR")" 1; fi
fi
[ "$COMPROMISE" -eq 0 ] && grn "$(msg CHECK_NO_HITS_OK)"

# =============================================================================
hdr "$(msg HDR_BLOCK6)"
# =============================================================================
HAPEER=$(cg '^add HA node ' | awk '{print $5}' | head -1)
if [ "$COMPROMISE" -eq 1 ]; then
  ACTION=FORENSICS_FIRST; RC=2; out "$(msg TAG_ACTION): FORENSICS_FIRST" 1 R
  out "$(msg VERDICT_FORENSICS_HEAD)" 1
  out "$(msg VERDICT_FORENSICS_STEP1)" 1
  out "$(msg VERDICT_FORENSICS_STEP2)" 1
  out "$(msg VERDICT_FORENSICS_STEP3)" 1
elif [ "$VULN" -eq 1 ] || [ "$VULN9" -eq 1 ]; then
  ACTION=UPDATE; RC=2; out "$(msg TAG_ACTION): UPDATE" 1 R
  if [ "$VULN" -eq 1 ]; then
    _ocve=$(grep '^OPEN' "$WORK/cve.txt" 2>/dev/null | awk '{print $2}' | sort -u | tr '\n' ',' | sed 's/,$//; s/,/, /g'); _octx=$(grep '^OPEN' "$WORK/cve.txt" 2>/dev/null | awk '{print $3}' | sort -u | tr '\n' ',' | sed 's/,$//; s/,/, /g')
    _oexp=""; grep '^OPEN' "$WORK/cve.txt" 2>/dev/null | grep -qE 'CVE-2026-(88771|88772|109618|109619) ' && _oexp="$(msg VERDICT_EXPLOITED_FRAG)"
    if [ "$EOL" -eq 1 ]; then out "$(msg VERDICT_UPDATE_EOL "$REL")" 1
    elif [ -n "$_ocve" ]; then out "$(msg VERDICT_UPDATE_VULN "$BUILD" "$_ocve" "$_octx" "$_oexp" "$TRAIN" "${FIXMAX:-?}")" 1
    else out "$(msg VERDICT_UPDATE_INCOMPLETE "$BUILD")" 1; fi
  fi
  [ "$VULN9" -eq 1 ] && out "$(msg VERDICT_UPDATE_SAML "$(grep '^SAMLOPEN' "$WORK/cve.txt" | awk '{print $2}' | sort -u | tr '\n' ' ')" "$TRAIN" "${FIXMAX:-?}")" 1
  [ "$TRACES" -eq 1 ] && out "$(msg VERDICT_UPDATE_TRACES)" 1
  [ "$TRACES" -eq 0 ] && out "$(msg VERDICT_UPDATE_NO_TRACES)" 1
  [ "$ISN_OPEN" -eq 1 ] && out "$(msg VERDICT_UPDATE_ISN)" 1
  out "$(msg VERDICT_UPDATE_HA)" 1
elif [ "$ISN_OPEN" -eq 1 ] || { [ "$TRACES" -eq 1 ] && [ "$MITIG_OK" -eq 0 ]; } || [ "$YEL_COUNT" -gt 0 ] || [ "$COVERAGE" = partial ]; then
  ACTION=INVESTIGATE; RC=1; out "$(msg TAG_ACTION): INVESTIGATE" 1 Y
  [ "$COVERAGE" = partial ] && out "$(msg VERDICT_INV_COVERAGE "${COVERAGE_WHY}")" 1
  out "$(msg VERDICT_INV_HEAD)" 1
  out "$(msg VERDICT_INV_REPEAT)" 1
  out "$(msg VERDICT_INV_OPEN_POINTS)" 1
  [ "$ISN_OPEN" -eq 1 ] && out "$(msg VERDICT_INV_ISN)" 1
  [ "$TRACES" -eq 1 ] && out "$(msg VERDICT_INV_TRACES)" 1
  [ "$UNSAVED" -eq 1 ] && out "$(msg VERDICT_INV_UNSAVED)" 1
  out "$(msg VERDICT_INV_IOC_SCAN)" 1
else
  ACTION=OK; RC=0; out "$(msg TAG_ACTION): OK" 1 G
  if [ "$ORG_COUNT" -gt 0 ]; then out "$(msg VERDICT_OK_COVERED "$ORG_COUNT")" 1
  else out "$(msg VERDICT_OK)" 1; fi
fi
[ "$SAVE_MISSING" -eq 1 ] && out "$(msg VERDICT_SAVE_MISSING_NOTE "$CONFBUILD")" 1
[ -n "$HAPEER" ] && out "$(msg VERDICT_HA_PEER "$HAPEER" "$SELFDIR" "$(basename "$SELF")" "$HOURS")" 1
out "" 1
BLOCKED_SEEN=$(awk -F'\t' '$5 != "" { print $2 }' "$JIPS" 2>/dev/null | sort -u | grep -c .)
# Adressen dieses Laufs mit Status gegenueber dem Bestand (kumulierte Liste, Stand vor diesem Lauf) und Sperrliste
if [ -s "$JIPS" ]; then
  _cumf="$(dirname "${OUTFILE:-.}")/ns_quickcheck_observed_ips.tsv"; [ "$NO_OUT" -eq 1 ] && _cumf=""
  out "$(msg ADDR_RUN_LIST_HEAD)" 1
  sort "$JIPS" | awk -F'\t' '{ k=$1 FS $2; n[k]+=$3; bl[k]=$5 } END { for (k in n) printf "%s\t%d\t%s\n", k, n[k], bl[k] }' | sort -t"$(printf '\t')" -k2,2 -k1,1 \
  | while IFS="$(printf '\t')" read -r _cat _ip _n _bl; do
      _st="$(msg ADDR_STATUS_NEW)"; if [ -n "$_cumf" ] && [ -f "$_cumf" ]; then _row=$(grep -v '^#' "$_cumf" | awk -F'\t' -v c="$_cat" -v i="$_ip" '$1==c && $2==i { if (NF>=11) print $8 "\t" $7 "\t" $9; else print $5 "\t" $4 "\t" $6; exit }')
        if [ -n "$_row" ]; then _f=$(echo "$_row" | cut -f1 | cut -c1-10); _d=$(echo "$_row" | cut -f2); _l=$(echo "$_row" | cut -f3 | cut -c1-10); [ "$_l" != "$(date +%Y-%m-%d)" ] && _d=$((_d + 1)); _st="$(msg ADDR_STATUS_KNOWN "$_f" "$_d")"; fi; fi
      _bs="$(msg ADDR_BLOCKED_NO)"; [ -n "$_bl" ] && { _sd=$(echo "$_bl" | cut -d'|' -f2); _bs="$(msg ADDR_BLOCKED_SINCE "${_sd:-$(msg CHECK_UNKNOWN)}")"; }
      _te=$(trusted_expired_info "$_ip"); [ -n "$_te" ] && _bs="$_bs$(msg TRUST_EXPIRED_LIST_FRAG "$_te")"
      case "$_cat" in trusted_*) _ti=$(trusted_info "$_ip"); _tt=${_ti#*|}; _tm=${_ti%%|*}; if [ -n "$_tt" ]; then _bs="trusted$(msg TRUST_UNTIL_FRAG "$_tt")"; else _bs="trusted$(msg TRUST_UNLIMITED_FRAG)"; fi; [ -n "$_tm" ] && _bs="$_bs$(msg TRUST_NOTE_FRAG "$_tm")" ;; esac
      out "  $(printf '%-18s %-22s %-32s %s' "$_ip" "$_cat" "$_st" "$_bs")" 1
    done
  _tot=$(sort "$JIPS" | cut -f1,2 | sort -u | grep -c .); out "$(msg ADDR_RUN_LIST_TOTAL "$_tot")" 1
  out "" 1
fi
VULN_OPEN=$(grep -c "^OPEN" "$WORK/cve.txt" 2>/dev/null); VULN_OPEN=${VULN_OPEN:-0}
RESULT="RESULT host=$HOST build=${BUILD:-?} mode=$MODE cli=$CLI_MODE window=${HOURS}h saml=$SAML vuln96=$VULN96 vuln_open=$VULN_OPEN vuln63=$VULN63 vuln79=$VULN9 isn_open=$ISN_OPEN traces=$TRACES mitigation=$MITIG_OK unsaved=$UNSAVED save_missing=$SAVE_MISSING compromise=$COMPROMISE red=$RED_COUNT yellow=$YEL_COUNT orange=$ORG_COUNT blocked_seen=${BLOCKED_SEEN:-0} trusted_seen=$TRUST_COUNT crashes=${NCRASH:-0} lang=$MSG_LANG coverage=$COVERAGE action=$ACTION rules=$RULES_VERSION script_sha256=${SCRIPT_SHA:-?} rules_sha256=${RULES_SHA:-?} msg_sha256=${MSG_SHA256:-?} custom=${CUSTOM_VERSION:-none} custom_sha256=${CUSTOM_SHA:-none} cve_custom=${CVE_CUSTOM_N:-0} cve_conflict=${CVE_CONFLICT_N:-0} runtime=$(( $(date +%s) - NOW ))s"
[ "${FOOTER:-1}" -eq 1 ] && { out "" 1; out "$(msg FOOT_CREATED "$VERSION" "$RULES_VERSION")" 1; }
out "$RESULT" 1

# --- JSON ----------------------------------------------------------------------
if [ "$NO_OUT" -eq 0 ]; then
  IPSFILE="${OUTFILE%.txt}_ips.tsv"
  { echo "$(msg ADDR_IPS_HEAD1)"
    echo "$(msg ADDR_IPS_HEAD2)"
    echo "$(msg ADDR_IPS_HEAD3)"
    echo "$(msg ADDR_IPS_HEAD4)"
    sort "$JIPS" | awk -F'\t' '{ k=$1 FS $2; n[k]+=$3; src[k]=$4; bl[k]=$5 } END { for (k in n) printf "%s\t%d\t%s\t%s\n", k, n[k], src[k], bl[k] }' | sort
  } > "$IPSFILE"; chmod 600 "$IPSFILE" 2>/dev/null
  NIPS=$(grep -cv '^#' "$IPSFILE")
  # kumulierte Liste je Appliance: Bestand plus Lauf, Schluessel Kategorie plus Adresse
  CUM="$(dirname "$OUTFILE")/ns_quickcheck_observed_ips.tsv"; TSH=$(date +'%Y-%m-%d %H:%M'); NEWIPS=0
  if [ "$NIPS" -gt 0 ] || [ -f "$CUM" ]; then
    { grep -v '^#' "$CUM" 2>/dev/null | awk '{ printf "B\t%s\n", $0 }'; grep -v '^#' "$IPSFILE" | awk '{ printf "L\t%s\n", $0 }'; } \
      | awk -F'\t' -v ts="$TSH" -v hrs="$HOURS" '
        # Bestand: neues Format 11 Spalten (NF==11); altes Format 8 Spalten (anzahl_gesamt, laeufe/tage) wird uebernommen: Summe als max, Fenster unbekannt (0)
        $1=="B" && NF>=12 { k=$2 FS $3; n[k]=$4; nw[k]=$5; mxn[k]=$6; mxw[k]=$7; r[k]=$8; f[k]=$9; l[k]=$10; o[k]=$11; b[k]=$12; next }
        $1=="B" { k=$2 FS $3; n[k]=$4; nw[k]=0; mxn[k]=$4; mxw[k]=0; r[k]=$5; f[k]=$6; l[k]=$7; o[k]=$8; b[k]=$9; next }
        $1=="L" { k=$2 FS $3; if (k in n) { n[k]=$4; nw[k]=hrs; if ($4+0 > mxn[k]+0) { mxn[k]=$4; mxw[k]=hrs } if (substr(l[k],1,10) != substr(ts,1,10)) r[k]++; l[k]=ts } else { n[k]=$4; nw[k]=hrs; mxn[k]=$4; mxw[k]=hrs; r[k]=1; f[k]=ts; l[k]=ts; o[k]=$5; new++ } b[k]=$6 }
        END { for (k in n) printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", k, n[k], nw[k], mxn[k], mxw[k], r[k], f[k], l[k], o[k], b[k]; printf "%d\n", new+0 > "/dev/stderr" }' 2>"$WORK/cum.new" | sort > "$WORK/cum.tsv"
    NEWIPS=$(cat "$WORK/cum.new"); CUMN=$(grep -c . "$WORK/cum.tsv"); SINCE=$(head -1 "$CUM" 2>/dev/null | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1); [ -n "$SINCE" ] || SINCE="$TSH"
    { echo "$(msg ADDR_CUM_HEAD1 "$HOST" "$SINCE" "$CUMN" "$TSH")"
      echo "$(msg ADDR_CUM_HEAD2)"
      echo "$(msg ADDR_CUM_HEAD3)"
      echo "$(msg ADDR_CUM_HEAD4)"
      echo "$(msg ADDR_CUM_HEAD5)"
      echo "$(msg ADDR_CUM_HEAD6)"
      echo "$(msg ADDR_CUM_HEAD7)"
      cat "$WORK/cum.tsv"; } > "$CUM"; chmod 600 "$CUM" 2>/dev/null
  fi
  [ -f "$WORK/hits.tsv" ] || : > "$WORK/hits.tsv"
  RESULT="$RESULT" HOST="$HOST" TS="$TS" JRED="$JRED" JYEL="$JYEL" JFIND="$JFIND" IPSFILE="$IPSFILE" VER="$VERSION" HITS="$WORK/hits.tsv" perl -e '
    sub j { my $s=shift; $s =~ s/\\/\\\\/g; $s =~ s/"/\\"/g; $s =~ s/[\x00-\x1f]/ /g; return "\"$s\"" }
    sub lst { my $f=shift; open(my $h,"<",$f) or return "[]"; my @a=map { chomp; j($_) } <$h>; close $h; return "[".join(",",@a)."]" }
    my %kv = map { /^([^=]+)=(.*)$/ ? ($1,$2) : () } split / /, $ENV{RESULT};
    delete $kv{RESULT};
    print "{\n  \"script\": \"ns_quickcheck\", \"version\": ".j($ENV{VER}).", \"host\": ".j($ENV{HOST}).", \"ts\": ".j($ENV{TS}).",\n";
    print "  \"result\": {".join(", ", map { j($_).": ".j($kv{$_}) } sort keys %kv)."},\n";
    my $hits = "{}";
    if (open(my $hh,"<",$ENV{HITS})) { my @p; while (<$hh>) { chomp; my ($n,$v)=split /\t/; push @p, j($n).": ".j($v) if defined $v } close $hh; $hits="{".join(",",@p)."}" }
    print "  \"mitigation_hits\": $hits,\n";
    my @ips; if (open(my $ih,"<",$ENV{IPSFILE})) { while (<$ih>) { chomp; next if /^#/; my ($k,$ip,$n,$src,$bl)=split /\t/; push @ips, "{\"category\": ".j($k).", \"ip\": ".j($ip).", \"count\": ".($n+0).", \"observed_in\": ".j($src).", \"blocked\": ".j(defined $bl ? $bl : "")."}" if defined $ip } close $ih }
    print "  \"observed_ips\": [".join(",",@ips)."],\n";
    my (@red,@yel,@org,@tru,$cur);
    if (open(my $fh,"<",$ENV{JFIND})) { while (<$fh>) { chomp; my ($k,$t)=split /\t/,$_,2; next unless defined $t;
        if ($k eq "R") { $cur={text=>$t,d=>[]}; push @red,$cur } elsif ($k eq "Y") { $cur={text=>$t,d=>[]}; push @yel,$cur } elsif ($k eq "O") { $cur={text=>$t,d=>[]}; push @org,$cur } elsif ($k eq "T") { $cur={text=>$t,d=>[]}; push @tru,$cur } elsif ($k eq "D" && $cur) { push @{$cur->{d}},$t } } close $fh }
    sub fl { my @a=@_; return "[".join(",", map { "{\"text\": ".j($_->{text}).", \"details\": [".join(",", map { j($_) } @{$_->{d}})."]}" } @a)."]" }
    print "  \"red\": ".fl(@red).",\n  \"yellow\": ".fl(@yel).",\n  \"orange\": ".fl(@org).",\n  \"trust\": ".fl(@tru).",\n  \"source_url\": \"https://ceterion.com/netscaler-quickcheck\"\n}\n";
  ' > "$JSONFILE" 2>/dev/null
  chmod 600 "$OUTFILE" "$JSONFILE" 2>/dev/null
  anon_map_build
  AHOST=$(awk -F'\t' -v h="$HOST" '$1=="host" && $2==h { print $3; exit }' "$ANON_MAP"); [ -n "$AHOST" ] || AHOST="gw-00"
  ANON_TXT="$(dirname "$OUTFILE")/ns_quickcheck_${AHOST}_${TS}_anon.txt"; ANON_JSON="${ANON_TXT%.txt}.json"
  _skipped=$(awk -F'\t' -v re="$ANON_RESERVED" '($1=="user" || $1=="mail") && (length($2) < 3 || tolower($2) ~ tolower(re)) { print $2 }' "$ANON_MAP" 2>/dev/null | tr '\n' ' ' | sed 's/ $//')
  { echo "$(msg HDR_ANON_REPORT_NOTE "$(wc -l < "$ANON_MAP" | tr -d ' ')" "$( [ -n "$_skipped" ] && echo "$(msg HDR_ANON_SKIPPED_FRAG "$_skipped")")")"; cat "$OUTFILE"; } > "$WORK/anon_in.txt"
  anon_apply "$WORK/anon_in.txt" "$ANON_TXT"
  anon_apply "$JSONFILE" "$ANON_JSON"
  # Adresslisten: anonymisierte Fassungen (Hostname, Bemerkungen der Sperr- und Vertrauensliste entfernt) und Share-Datei
  anon_list() { # infile outfile  (Spalten beobachtung und gesperrt bereinigen, dann Zuordnungstabelle)
    awk -F'\t' 'BEGIN { OFS="\t" } /^#/ { print; next }
      { for (i=1;i<=NF;i++) { if ($i ~ /\(trusted/) { sub(/: [^)]*\)/, ")", $i) }
          if ($i ~ /\|/ && $i !~ /^http/) { n=split($i, g, "|"); $i=(n>=2 ? g[2] : "") } } print }' "$1" > "$WORK/anon_list.tmp"
    anon_apply "$WORK/anon_list.tmp" "$2"; chmod 600 "$2" 2>/dev/null; }
  if [ -f "$IPSFILE" ]; then ANON_IPS="$(dirname "$OUTFILE")/ns_quickcheck_${AHOST}_${TS}_ips_anon.tsv"; anon_list "$IPSFILE" "$ANON_IPS"; fi
  if [ -f "${CUM:-}" ]; then ANON_CUM="$(dirname "$OUTFILE")/ns_quickcheck_observed_ips_anon.tsv"; anon_list "$CUM" "$ANON_CUM"
    SHARE="$(dirname "$OUTFILE")/ns_quickcheck_${AHOST}_${TS}_share.tsv"
    { echo "$(msg SHARE_HEAD "$VERSION" "$(date +%Y-%m-%d)")"
      echo "# kategorie	ip	zuerst	zuletzt	tage	anzahl_max	max_fenster_h	anzahl_zuletzt	regeldatei"
      grep -v '^#' "$CUM" | awk -F'\t' -v re="${ATTACKER_IP_RE:-^$}" 'BEGIN { OFS="\t" }
        $1=="payload_download_host" || $1=="injection_source" || $1=="webshell_hit" || $1=="outbound_hit" || $1=="aaa_bruteforce" || $1=="aaa_maschine" || $1=="aaa_hit" || $1=="ssh_bruteforce" || ($1=="dropper_requester" && $5+0 >= 3) {
          rf = ($2 ~ re) ? "ja" : "nein"; print $1, $2, substr($8,1,10), substr($9,1,10), $7, $5, $6, $3, rf }' | sort -u; } > "$SHARE"; chmod 600 "$SHARE" 2>/dev/null
  fi
  [ "${NIPS:-0}" -gt 0 ] && echo "$(msg ADDR_RUN_SUMMARY "${OUTFILE%.txt}" "$NIPS" "${NEWIPS:-0}" "${BLOCKED_SEEN:-0}" "${SINCE:-$(msg ADDR_SINCE_TODAY)}" "${CUMN:-0}")"
  echo "$(msg FOOT_FILES "$OUTFILE" "$JSONFILE" "$ANON_TXT" "$ANON_JSON")"
  [ -n "${ANON_CUM:-}" ] && echo "$(msg SHARE_FILES "${ANON_IPS:-}" "$ANON_CUM" "${SHARE:-}")"
  [ "$MODE" = online ] && find "$REPORT_DIR" -maxdepth 1 -type f -name 'ns_quickcheck_*' -mtime +"$REPORT_KEEP_DAYS" -delete 2>/dev/null
fi
CLI_PW=""
exit $RC
