# ns_quickcheck: Sicherheits-Triage für NetScaler ADC und Gateway

Ein Lauf auf der Appliance, ein Verdict: Build gegen die Citrix-Bulletins, Angriffsspuren, Kompromittierungs-Schnellcheck, Adresslisten, anonymisierte Reports. Regelgesteuert, offline-fähig, erweiterbar durch eigene Indikatoren. Entstanden im Oktober 2026 für CTX697096, CTX697174 und CTX697191, gebaut für die Bulletins danach.

Script V17.43, Regeldatei Format 2 (Stand 2026-10-28e), README v36 (2026-10-28); die Fassung im Repository ist immer die zum Script passende, die Historie steht in Abschnitt 17. Apache 2.0, Copyright 2026 ceterion AG.

Für wen welcher Abschnitt ist: **Betreiber** (Admin, der das Script laufen lässt): 1 bis 7, 10, 11, 12, 15, 16; wer Schwellen anpasst: 4.2 und 4.3. **Betreiber mit eigenen Indikatoren**: zusätzlich 8.4 bis 8.6 und WORKFLOW.de.md. **ceterion und Power-User** (Regelpflege, Abnahme, Tests): 8, 9, 13.

## 1. In 15 Minuten

1. Aus dem Release `ns_quickcheck.sh` und `ns_quickcheck.rules` laden, SHA-256 gegen die Release-Seite prüfen.
2. Per SCP (WinSCP: Binary) nach `/var/nssnapshot/` auf die Appliance; das Verzeichnis anlegen, falls es fehlt (es bleibt bei Neustarts erhalten, anders als `/var/tmp`). Dort als `nsroot`:
   ```
   mkdir -p /var/nssnapshot && cd /var/nssnapshot
   chmod 600 ns_quickcheck.sh ns_quickcheck.rules
   sh ns_quickcheck.sh
   ```
3. Exit-Code lesen (`echo $?` direkt nach dem Lauf): 0 `OK`, 1 `INVESTIGATE`, 2 `UPDATE` oder `FORENSICS_FIRST`, 3 Abbruch mit Grund auf stderr (Regeldatei fehlt, Kernvariable fehlt, Option ohne Wert). 1 und 2 sind Verdicts, keine Fehler. Bricht der Lauf ohne `RESULT`-Zeile ab, mit `sh -x ns_quickcheck.sh --no-out 2>/tmp/qc_trace.txt >/tmp/qc_out.txt` wiederholen und beide Dateien anonymisiert einsenden (`--anon`, Abschnitt 5.3).
4. Kopfzeile lesen: `ns_quickcheck 17.43  host=<name>  modus=online  regeln=2026-10-28e`. Steht dort `cli=none`, fehlt die CLI-Ebene (Abschnitt 3); das Script läuft trotzdem. Darunter stehen die geladenen Betreiberdateien (Custom, Sperrliste, Whitelist) und in Block 4 die gelesenen Logfamilien mit Dateizahl.
5. Ans Ende blättern: `ACTION: OK`, `UPDATE`, `INVESTIGATE` oder `FORENSICS_FIRST`. Was das heißt, steht in Abschnitt 7, Tabelle "Jetzt tun".
6. Vor der `RESULT`-Zeile stehen die fremden Adressen dieses Laufs mit Status (neu oder bekannt seit) und Sperrstatus; `coverage=full` in `RESULT` bestätigt, dass alle Kernprüfungen Daten hatten.
7. Alle weiteren Dateien (Config, Whitelist, Sperrliste, Custom-Datei, Zuordnungstabelle) gehören in dasselbe Verzeichnis. Die Dateien dieses Laufs liegen in `/var/nssnapshot/quickcheck/`: Report, JSON, Adressliste, anonymisierte Fassungen. Nach außen geht nur `_anon.*` (Abschnitt 5.3).

So sieht ein sauberer Lauf aus (gekürzt, anonymisiert; `fenster=168h` stammt hier aus `HOURS=168` in der Config, die Vorgabe des Scripts ist 72 h):

```
ns_quickcheck 17.43  host=gw-01  modus=online  fenster=168h  regeln=2026-10-28e  cli=nscli (user01, cli_user aus ns_snapshot.conf)
  [INFO]  Custom-Datei des Betreibers geladen: 78 aktive Indikator-Zeile(n), 0 CVE-Zeile(n) (betreiber-2026-10-20)
  [INFO]  Sperrliste: 3 Eintrag/Eintraege (ns_quickcheck.blocked_ips und ACLs der Appliance); Befunde zu gesperrten Adressen vor dem Sperrdatum werden ORANGE (abgedeckt)
Whitelist: /var/nssnapshot/ns_quickcheck.whitelist (4 Regeln)
== 1 Build ==
  [OK]    Build 14.1-73.46 enthaelt alle 11 Fix(es) fuer 14.1 der Regeldatei
  [INFO]  Letzter Boot: 2026-10-09 06:10 (12 Tage)
== 2 Exposure ==
  [OK]    Kein SAML SP/IdP - SAML-abhaengige CVEs nicht relevant
  [INFO]  DTLS an 4 Gateway-vServer aktiv (CVE-2026-88772-Voraussetzung; auf gefixtem Build mitigiert)
  [OK]    Enhanced ISN Generation aktiv
== 3 Mitigation ==
  [INFO]  Keine Mitigation-Policy gefunden (auf gefixtem Build ohne Spuren nicht erforderlich)
== 4 Angriffsspuren (letzte 168h) ==
  [INFO]  Gelesene Logs im Fenster: ns.log/nsvpn/messages/notice 84, httpaccess 15, httperror 3, auth.log 8, httpaccess.log (Management) 2, cron 4 Datei(en)
  [OK]    Keine Injection-Muster in Logon-Zeilen der letzten 168h
  [OK]    Keine nsaaad-Crashes im Fenster
  [OK]    Webserver-Fehlerlog ohne Interpreter-Fehler ausserhalb der Stock-Pfade
  [OK]    Keine Webshell-Sondierung im Webserver-Fehlerlog
  [OK]    Management-Ebene (NITRO, GUI) nur von internen Adressen angesprochen
  [INFO]  Anmeldungen an der Appliance im Fenster: console (2) nur interne Adressen
  [INFO]  Gateway-Anmeldefehler im Fenster: 14, keine Adresse ueber den Schwellen (5 Fehlversuche, 10 Konten)
== 5 Kompromittierungs-Schnellcheck ==
  [OK]    netscaler/ns_monuploadd_err.pl: Hash entspricht dem Stock-Wert fuer 14.1-73.46
  [OK]    Keine Schnellcheck-Treffer (ersetzt keinen vollen IoC-Scan)
== 6 Verdict ==
ACTION: OK
Build gefixt, keine Spuren. Naechster Lauf nach dem naechsten Bulletin oder taeglich per Cron.
RESULT host=gw-01 build=14.1-73.46 ... compromise=0 red=0 yellow=0 orange=0 coverage=full action=OK rules=2026-10-28e ...
```

Ein exponiertes Gateway sieht an den meisten Tagen nicht so aus: Sondierungen, Dropper-Anfragen und Anmeldefehler sind Alltag. Was dann zu tun ist, steht in den "Zu tun"-Zeilen der Befunde und in Abschnitt 15 unter "Alles ist Gelb".

Was das Script nicht tut: Es ändert nichts an der Appliance, patcht nicht, baut keine Netzwerkverbindung auf, sendet nichts. Es liest Konfiguration, Logs, Dateisystem, Prozesse und Listener und schreibt Reports in ein Verzeichnis. Es ist keine Forensik; es sagt, ob Forensik nötig ist, bevor jemand patcht.

## 2. Zweck und Einordnung

Ein Betreiber mit NetScaler Gateway oder ADC muss nach einem Bulletin drei Fragen beantworten: Ist der Build offen? Gibt es Spuren eines Angriffs? Darf ich patchen, oder zerstört das Upgrade Beweise? Das Script beantwortet alle drei in einem Lauf auf der Appliance, ohne Abhängigkeiten, online oder offline gegen ein Snapshot-Set.

Seit 17.19 prüft das Script auch, was nicht in einem Bulletin steht und trotzdem jeden Tag passiert: Webshell-Sondierungen, Zugriffe auf die Management-Ebene, SSH-Anmeldungen und Angriffe auf Gateway-Konten (Password Spraying, Brute Force, langsame "Schläfer"), mit Quellen, Netzen und Sperrstatus; dafür liest es neben den Syslogs auch Access-, Fehler- und Anmeldelogs.

Die Bewertung steht in der Regeldatei (Fix-Builds, Bedingungen, Indikatoren, Muster), nicht im Script; ein neues Bulletin ist ein neuer Regelstand. Betreiber können eigene Indikatoren und Fix-Builds in einer Custom-Datei pflegen (8.4). Verwandte Werkzeuge: `netscaler-snapshot` (täglicher Datei-Snapshot) und `netscaler-collector` (Auswertung über Geräte und Zeit), Abschnitt 14.

## 3. Voraussetzungen

| Punkt | Online (auf der Appliance) | Offline (Admin-Rechner) |
|---|---|---|
| System | NetScaler 13.1 oder 14.1, root-Shell (`shell` aus der CLI) | Linux, macOS oder WSL mit `sh`, `perl`, `gzip`, `find`, `awk` |
| Eingabe | laufende Appliance | entpacktes Snapshot-Archiv 1 (Config, Manifest, State), optional Archiv 3 (Logs) |
| Regeldatei | `ns_quickcheck.rules` neben dem Script oder per `--rules`; Rechte 600 | gleich |
| Custom-Datei | `ns_quickcheck.rules.custom` neben der Regeldatei, optional, 600 | gleich |
| Config | `ns_quickcheck.conf` (optional) und `ns_snapshot.conf` (nur `CLI_*`), root-owned, 600 | optional |
| Whitelist | `ns_quickcheck.whitelist` (optional), je Appliance | optional |
| CLI-Ebene | Service-User (3.1); aus `ns_snapshot.conf`, falls der Snapshot läuft, sonst aus `ns_quickcheck.conf`; ohne ihn fehlen Hit-Counter, Deny-List, Sessions und der Diff laufende/gespeicherte Config | nicht verfügbar |
| Arbeitsverzeichnis | `/var/nssnapshot/tmp` (Vorgabe) oder `WORK_BASE` aus der Config; nie `/tmp`, das liegt auf dem kleinen Root-Dateisystem | `/var/tmp` |

Gelesene Logs (alle unter `/var/log/`, Rotationen `.N.gz` eingeschlossen, Auswahl nach Änderungszeit im Fenster `--hours`):

| Familie | Wofür | Fehlt sie im Fenster |
|---|---|---|
| `ns.log`, `nsvpn.log`, `messages`, `notice.log` | Injection-Zeilen, nsaaad-Crashes, DTLS-Fehler, Gateway-Anmeldungen (AAA) | Gelb und `coverage=partial`, das Verdict wird nie `OK` |
| `httpaccess-vpn.log`, `httpaccess.log` | Dropper-Anfragen, Quellen von Sondierungen, Webshell-Pfade mit Status 200, Management-Zugriffe (nur `httpaccess.log`) | INFO "nicht geprüft" und `coverage=partial` |
| `httperror.log`, `httperror-vpn.log` | Interpreter-Fehler, Webshell-Sondierung, direkte Webserver-Zugriffe | INFO "nicht geprüft" |
| `auth.log` | SSH- und Konsolenanmeldungen, Fehlversuche, Backdoor-Konten | INFO "nicht geprüft" |
| `cron` | letzter Lauf fremder Crontab-Zeilen | Zeile entfällt |
| `nsinstall.log` | Zeitpunkt des letzten Upgrades für das Upgrade-Fenster in Block 5 | Boot-Zeit allein |

### 3.1 Service-User für die CLI-Ebene (optional, empfohlen)

Ohne ihn fehlen Hit-Counter der Mitigation-Policies, Deny-List, aktive Sessions und der Diff laufende gegen gespeicherte Config; das Verdict läuft trotzdem. Wer `netscaler-snapshot` einsetzt, hat den User schon (`CLI_USER` in `ns_snapshot.conf`), der Quickcheck nutzt ihn mit. Sonst einmalig je Appliance. HA-Paar: CLI-Schritte nur auf dem Primary (der User synchronisiert), Secret-Datei auf beiden Knoten (sie synchronisiert nicht).

Prüfen, ob schon einer da ist: `grep CLI_USER /var/nssnapshot/ns_snapshot.conf`. Steht dort ein Name, nichts weiter tun; die Kopfzeile des nächsten Laufs zeigt `cli=nscli (<name>, cli_user aus ns_snapshot.conf)`. Trägt `ns_quickcheck.conf` eigene Werte, gewinnen diese.

Kontoname frei, hier `ns-quickcheck`; läuft der Snapshot, gibt es den User `ns-snapshot` schon, dann nichts anlegen und nichts eintragen; NetScaler unterscheidet Groß- und Kleinschreibung, deshalb durchgehend klein.

Schritt 1, Shell als root: Passwort erzeugen und ablegen
```
umask 077
mkdir -p /var/nssnapshot
openssl rand -base64 48 | tr -d '/+=\n' | cut -c1-32 > /var/nssnapshot/ns_quickcheck.secret
chown root:wheel /var/nssnapshot/ns_quickcheck.secret; chmod 600 /var/nssnapshot/ns_quickcheck.secret
cat /var/nssnapshot/ns_quickcheck.secret
```

Schritt 2, CLI: Policy, User, Bindung (Passwort aus Schritt 1 einsetzen, die CLI-Session danach beenden)
```
show system parameter
add system cmdPolicy cp_ns-quickcheck_ro ALLOW "(^show\s+(?!techsupport|system\s+(cmdPolicy|file)).*)|(^stat\s+.*)"
add system user ns-quickcheck <PASSWORT> -externalAuth DISABLED -allowedManagementInterface CLI -timeout 300 -maxsession 1
bind system user ns-quickcheck cp_ns-quickcheck_ro 100
save ns config
```
`localAuth` in `show system parameter` muss `ENABLED` sein. Die eingebaute Policy `read-only` reicht nicht, sie schließt `show ns runningConfig` aus.

Schritt 3, Shell als root: Test (der zweite und dritte Befehl müssen abgewiesen werden)
```
PW=$(cat /var/nssnapshot/ns_quickcheck.secret)
/netscaler/nscli -U %%:ns-quickcheck:$PW "show ns version"; echo RC=$?
/netscaler/nscli -U %%:ns-quickcheck:$PW "save ns config"; echo RC=$?
/netscaler/nscli -U %%:ns-quickcheck:$PW "shell"; echo RC=$?
unset PW
```

Schritt 4: in `ns_quickcheck.conf` eintragen, dann ein Lauf; die Kopfzeile zeigt `cli=nscli (ns-quickcheck)`.
```
CLI_USER=ns-quickcheck
CLI_SECRET_FILE=/var/nssnapshot/ns_quickcheck.secret
```

Was der Account kann: nur `show` und `stat`, nur CLI, keine externe Authentifizierung, eine Session, 300 s Timeout. Was er nicht kann: speichern, ändern, Shell, NITRO, GUI. Jede Abfrage erscheint als `CMD_EXECUTED` in `ns.log`; der Quickcheck schließt Admin-Befehle von der Bewertung aus und nimmt den `CLI_USER` automatisch aus der Prüfung lokaler System-User. Das Passwort steht während eines `nscli`-Aufrufs sekundenlang in der Prozessliste (Abschnitt 10).

Rückbau: `unbind system user ns-quickcheck cp_ns-quickcheck_ro`, `rm system user ns-quickcheck`, `rm system cmdPolicy cp_ns-quickcheck_ro`, `save ns config`, danach `rm /var/nssnapshot/ns_quickcheck.secret`.

## 4. Installation und Dateien

### 4.1 Dateien und Update

| Datei | Ort | Rechte | Beim Update |
|---|---|---|---|
| `ns_quickcheck.sh` | `/var/nssnapshot/` | 600, root:wheel | ersetzen |
| `ns_quickcheck.rules` | neben dem Script | 600 | ersetzen |
| `ns_quickcheck.rules.custom` | neben der Regeldatei | 600 | bleibt |
| `ns_quickcheck.conf` | neben dem Script | 600 | bleibt |
| `ns_quickcheck.secret` | `/var/nssnapshot/` (Passwort des Service-Users, 3.1) | 600, root:wheel | bleibt; nie in Reports, Sets oder Issues |
| `ns_quickcheck.whitelist` | neben dem Script | 600 | bleibt |
| `ns_quickcheck.blocked_ips` | neben dem Script (Sperrliste des Betreibers, 5.4) | 600 | bleibt |
| `ns_quickcheck.anon.<host>.map` | neben der Regeldatei, entsteht beim ersten Lauf | 600 | bleibt |
| Reports | `/var/nssnapshot/quickcheck/` | 600 | bleiben, Löschung nach `REPORT_KEEP_DAYS` (30) |
| `ns_quickcheck_observed_ips.tsv` | im Reportverzeichnis | 600 | bleibt, keine Löschung |

Update: die zwei Dateien ersetzen, Hash prüfen, ein Lauf. Alles andere bleibt.

### 4.2 Konfiguration (`ns_quickcheck.conf`)

Optional, neben dem Script, 600; jede Zeile `NAME=wert`, fehlende Zeilen nehmen die Vorgabe. Vorlage `ns_quickcheck.conf.example`.

| Parameter | Vorgabe | Wirkung |
|---|---|---|
| `BASE_DIR` | `/var/nssnapshot` | Ablage für Reports (`quickcheck/`), Secret, Arbeitsverzeichnis |
| `HOURS` | 72 | Logfenster in Stunden, wie `--hours`; die Option gewinnt |
| `WORK_BASE` | `$BASE_DIR/tmp`, Rückfall `/var/tmp` | Zwischendateien und Entpacken bei `--compare`; nie `/tmp` |
| `REPORT_KEEP_DAYS` | 30 | Löschung alter Reports; die kumulierte Adressliste bleibt |
| `ACCESS_LOG_MAX_MB` | 200 | Obergrenze gelesener `httpaccess*`-Dateien, jüngste zuerst |
| `CLI_TIMEOUT` | 20 | Sekunden je `nscli`-Aufruf |
| `CLI_USER`, `CLI_SECRET_FILE` | aus `ns_snapshot.conf`, falls der Snapshot läuft, sonst hier | Service-User (3.1) |
| `DETAIL_MAX` | 0 (alles) | Zeilen je Detailliste; darüber "... und n weitere" |
| `LINE_MAX` | 400 | Zeichen je Logzeile in Terminal und Report; 0 = ungekürzt; Injection-Zeilen immer vollständig |
| `MGMT_NET_RE` | leer (nur RFC 1918 gilt als intern) | ERE der Admin-Netze und Sprungserver; gilt für Management-Zugriffe, SSH-Logins, Webserver-Direktzugriffe und eigene Adressen bei Anmeldefehlern |
| `PROBE_LEVEL` | `yellow` | `info` stuft Webshell-Sondierungen auf eine INFO-Zeile ab |
| `CORE_BOOT_LEVEL` | `info` | leeres Core-Verzeichnis `/var/core/<n>` innerhalb 15 min nach Boot als INFO (Boot-Nachlauf) oder `yellow` als Absturz-Ereignis |
| `TRUST_LEVEL` | `trust` | vertraute Adressen als eigene Stufe `[TRUST]` ohne Verdict-Wirkung; `yellow` macht Gelb daraus |
| `FOOTER` | 1 | Fußzeile "Erstellt mit netscaler-quickcheck ..." im Report und in den anon-Fassungen; 0 schaltet ab |
| `PHP_ANOMALY_MIN` | 3 | PHP-Speicher-/Fatal-Muster im Management-Portal (CTX697263), ab so vielen Zeilen im Fenster gemeldet; auf gefixtem Build nur INFO |
| `AAA_FAIL_IP` | 5 | Gateway-Anmeldefehler je Adresse, ab denen die Adresse bewertet wird |
| `AAA_FAIL_USERS` | 10 | verschiedene Konten je Adresse, ab denen sie Maschine ist |
| `AAA_RATE` | 10 | Fehlversuche je Minute, ab denen eine Adresse Maschine ist |
| `AAA_OK_WIN` | 5 | Minuten nach dem letzten Fehlversuch, in denen ein Erfolg desselben Kontos von derselben Adresse "Nutzer" bedeutet |
| `AAA_BF_MIN` | 20 | Fehlversuche auf ein einzelnes Konto, ab denen es Brute Force ist |
| `AAA_SLEEPER_DAYS` | 2 | Tage mit Versuchen oder Spanne zwischen erstem und letztem Versuch, ab der eine Adresse Schläfer ist |

### 4.3 Schwellen und Annahmen

Die Bewertungen in Block 4 und 5 beruhen auf Schwellen, die an einem Lab-Gateway kalibriert sind. Jede ist dokumentiert und, wo sinnvoll, in der Config änderbar. Wer Fehlalarme hat, dreht an der genannten Schraube; wer etwas übersieht, an der anderen Richtung.

| Annahme | Vorgabe | Fehlalarm, wenn | Übersehen, wenn |
|---|---|---|---|
| Dropper-Suche: mehr als zwei verschiedene Paketnamen von einer Adresse oder Kommandozeichen im Query-String | fest | nie beobachtet; echte Clients fragen ein Paket | Angreifer mit genau einem Paketnamen erscheint als Gelb, nicht Rot |
| Upgrade-Fenster: Dateiänderungen bis 15 min nach Boot und 30 min nach dem letzten Upgrade (`nsinstall.log`) gelten als Upgrade | fest | Angreifer, der in der halben Stunde nach dem Upgrade schreibt | sehr lange Upgrades (über 30 min) erzeugen Gelb für Stock-Dateien; Whitelist |
| Maschine: ab `AAA_RATE`/min oder `AAA_FAIL_USERS` Konten je Adresse, oder Adresse aus einem /24 mit mindestens zwei Maschinen | 10, 10 | Firmen-Proxy mit vielen Nutzern, die am selben Morgen scheitern (kommt als "Nutzer" heraus, sobald einer sich anmeldet) | Sprayer unter 10/min mit unter 10 Konten je Adresse: dafür der Schläfer |
| Nutzer: Erfolg desselben Kontos von derselben Adresse innerhalb `AAA_OK_WIN` | 5 min | Angreifer, der ein Passwort trifft (dann Treffer, Rot, wenn die Adresse Maschine ist) | Helpdesk-Fall nach 40 min bleibt "unklar" und verschwindet beim nächsten Lauf |
| Burst: ein Konto, mindestens 3 Versuche/min, alles innerhalb 10 min | fest | ein sehr schneller Mensch | Client mit altem Passwort, der langsamer probiert, steht als "unklar" |
| Schläfer: mehrere Konten, kein Erfolg, Versuche an `AAA_SLEEPER_DAYS` Tagen oder über diese Spanne | 2 | Nutzer, der an zwei Tagen zwei Konten probiert und aufgibt (selten; Kontenliste im Original zeigt es) | mit 1 würde jede Mehrkonten-Adresse ohne Erfolg Schläfer heißen, die Zeitachse ginge verloren |
| Brute Force: `AAA_BF_MIN` Fehlversuche auf ein Konto oder `AAA_RATE`/min auf ein Konto, von beliebig vielen Adressen | 20 | ein Nutzer mit 20 Fehlversuchen ohne Erfolg (steht dann mit Konto und Adresse im Report, meist der Helpdesk-Anruf) | geduldiger Angreifer unter 20 Versuchen im Fenster: Schläfer-Logik |
| Treffer: Erfolg nach Fehlserie einer Maschine (gleiche Adresse und Konto) oder nach Brute Force auf ein Konto (von jeder Adresse) | fest | der Nutzer meldet sich selbst nach dem Angriff an: deshalb "ein Mensch muss das entscheiden" | nie unterdrückt; Rot bleibt Rot |
| Quell-IP bei Logon-Zeilen: Request zur Versuchszeit, plus/minus 5 s, Offset-Suche bis 14 h | fest | unbeteiligter Logon derselben Sekunde (deshalb "passt zu n von m" und "schwach") | ein Versuch allein liefert keine Quelle (bewusst) |
| Quell-IP bei Responder-Zeilen: nur aus der Zeile selbst | fest | keiner | Policy ohne Audit-Message-Action: Quelle unbekannt (Howto Responder-Quelle) |
| PHP2Shell-Hinweis: ab `PHP_ANOMALY_MIN` PHP-Speicher-/Fatal-Zeilen im Management-Portal; Gelb nur auf verwundbarem Build, Rot nur mit neuer PHP-Datei im Fenster | 3 | große Configs erzeugen dieselben Meldungen in der GUI (deshalb INFO auf gefixtem Build) | Ausnutzung ohne Fehlermeldung (keine Signatur veröffentlicht); Block 5 bleibt die zweite Linie |
| Webshell-Sondierung: 404 für bekannte Webshell-Namen | fest | keiner, die Namen sind eindeutig | Angreifer mit eigenem Dateinamen: nur über Block 5 und den 200-Check |

Cron (täglich nach dem Snapshot, bootfest über `/nsconfig/rc.netscaler`):
```
# /nsconfig/rc.netscaler
echo '45 3 * * * root /bin/sh /var/nssnapshot/ns_quickcheck.sh --compare cron --brief >> /var/nssnapshot/quickcheck/cron.log 2>&1' >> /etc/crontab
```
`--brief` hält das Cron-Log kurz; der vollständige Report wird trotzdem geschrieben.

## 5. Aufruf

Jede Option mit Wert gibt es in zwei Schreibweisen: `--option wert` und `--option=wert`. Fehlt der Wert, bricht das Script mit Exit 3 und einer Meldung ab.

| Option | Wert | Wirkung | Vorgabe |
|---|---|---|---|
| `--hours` | Stunden | Logfenster: nur Logdateien, die in den letzten n Stunden geändert wurden; auch als `HOURS=` in der Config | 72 |
| `--from` | Pfad | Offline-Lauf gegen ein entpacktes Snapshot-Set (Archiv 1, optional Archiv 3) | online |
| `--compare` | `cron`, `latest` oder Pfad | Vergleich gegen das jüngste vollständige Set, das jüngste Set oder ein entpacktes Archiv 1: neue oder geänderte Web-Dateien, neue System-User, neue Listener | kein Vergleich |
| `--rules` | Pfad | Regeldatei; `ns_quickcheck.rules.custom` wird im selben Ordner gesucht | neben dem Script, sonst `/var/nssnapshot/` |
| `--pin`, `--pin-all` | Pfad | gibt Pin-Zeilen (`webfile:...$@sha256=<hash>`) für alle Code-Dateien (`--pin`) oder alle Dateien (`--pin-all`) unter dem Pfad aus und beendet sich; für die Whitelist (Howto Whitelist) | |
| `--whitelist` | Pfad | Whitelist je Appliance (`user:`, `listener:`, `path:`, `cron:`, `webfile:`) | neben dem Script |
| `--blocked` | Pfad | Sperrliste des Betreibers (5.4) | `ns_quickcheck.blocked_ips` neben dem Script |
| `--trusted` | Pfad | Vertrauensliste des Betreibers (5.5) | `ns_quickcheck.trusted_ips` neben dem Script |
| `--conf` | Pfad | Konfigurationsdatei (`BASE_DIR`, `WORK_BASE`, `REPORT_KEEP_DAYS`, `ACCESS_LOG_MAX_MB`, `CLI_TIMEOUT`, `DETAIL_MAX`, `MGMT_NET_RE`, `PROBE_LEVEL`, `LINE_MAX`, `AAA_FAIL_IP`, `AAA_FAIL_USERS`, `AAA_RATE`, `AAA_OK_WIN`, `AAA_BF_MIN`, `AAA_SLEEPER_DAYS`, `CLI_USER`, `CLI_SECRET_FILE`); wird vor allen anderen Optionen geladen | neben dem Script |
| `--out` | Pfad | Reportdatei; JSON, Adressliste und anon-Fassungen daneben | `/var/nssnapshot/quickcheck/ns_quickcheck_<host>_<zeit>.txt` |
| `--no-out` | | kein Report, nur Bildschirm; keine anon-Dateien, keine Adressliste | |
| `--anon` | Datei | beliebigen Logauszug mit der Zuordnungstabelle dieser Appliance anonymisieren, Ausgabe auf stdout, sonst nichts | |
| `--full` | | alles auf dem Bildschirm (seit 17.2 die Vorgabe; Option bleibt für Scripts) | |
| `--brief` | | nur Befunde und Kurzzeilen auf dem Bildschirm; Report bleibt vollständig; für Cron-Mails | |
| `--no-cli` | | CLI-Ebene auslassen, auch wenn ein Service-User konfiguriert ist (schneller; ohne Hit-Counter, Sessions, Config-Diff) | |
| `--testlog` | Ordner oder Datei | Regelmuster gegen Testlogs prüfen, Erwartungen aus `expected.txt`; Arbeitsplatz, nie Appliance | |
| `--ki-bundle` | | anonymisiertes Material für die Regelpflege nach `/var/tmp`; nur bei Abnahme auf neuer Build-Familie | |
| `--version` | | Script-Version ausgeben, Ende | |

Beispiele:
```
sh ns_quickcheck.sh                                         # Standardlauf online
sh ns_quickcheck.sh --compare cron --brief                  # Cron: Vergleich gegen das letzte vollstaendige Set, kurze Ausgabe
sh ns_quickcheck.sh --from /var/nssnapshot/tmp/x --rules /var/nssnapshot/ns_quickcheck.rules   # offline gegen ein entpacktes Set
sh ns_quickcheck.sh --anon /var/log/ns.log.1 > /var/tmp/ns.log.1.anon                          # Logauszug anonymisieren
sh ns_quickcheck.sh --anon=/var/tmp/auszug.txt                                                  # gleiche Option mit Gleichheitszeichen
```

### 5.1 Reportdateien je Lauf

| Datei | Inhalt | Darf nach außen |
|---|---|---|
| `ns_quickcheck_<host>_<zeit>.txt` | der Report, wie auf dem Bildschirm | nein |
| `ns_quickcheck_<host>_<zeit>.json` | RESULT-Felder, je Befund `text` und `details`, `observed_ips`, `mitigation_hits`; Adressen defanged | nein |
| `ns_quickcheck_<host>_<zeit>_ips.tsv` | beobachtete fremde Adressen dieses Laufs je Kategorie (5.2) | nach Prüfung |
| `ns_quickcheck_observed_ips.tsv` | kumulierte Adressliste der Appliance über alle Läufe (5.2) | nach Prüfung |
| `ns_quickcheck_<ersatzhost>_<zeit>_anon.txt` und `_anon.json` | anonymisierte Fassungen (5.3) | ja, nach Stichprobe |

### 5.2 Adressliste

Je Lauf schreibt das Script `ns_quickcheck_<host>_<zeit>_ips.tsv` in das Reportverzeichnis (Kopfzeilen mit `#`, dann je Zeile Kategorie, Adresse, Anzahl, Beobachtung, tabgetrennt); dieselben Einträge stehen im JSON als `observed_ips`. Die anon-Fassungen enthalten die Adressen ebenfalls, weil es fremde Adressen sind. Enthalten sind die fremden Adressen, die das Gerät in diesem Lauf gesehen hat, für Firewall und SOC:

| Kategorie | Herkunft | Für die Blockliste |
|---|---|---|
| `webshell_hit` | Quelle eines Requests auf einen Webshell-Pfad, der mit 200 geantwortet hat | sehr hoch: Kompromittierungszeichen |
| `webshell_probe`, `webserver_direct` | Quellen von Requests auf nicht existierende Webshell-Pfade; Clients, die den Webserver ohne Packet Engine erreichten | hoch: gezielte Sondierung |
| `aaa_bruteforce`, `aaa_sleeper`, `aaa_hit` | Maschinen-Adressen mit Gateway-Anmeldefehlern; `aaa_sleeper`: langsames Spraying über Tage; `aaa_hit`: Erfolg nach Fehlserie, Konto kompromittiert | hoch; `aaa_hit` sofort handeln |
| `mgmt_access`, `ssh_login_external`, `ssh_bruteforce` | Management-Pfade, SSH-Logins und Fehlversuche von Adressen außerhalb RFC 1918 und `MGMT_NET_RE` | prüfen: Admin-Netze in `MGMT_NET_RE` eintragen, sonst sperren |
| `payload_download_host` | Adresse im Injection-Payload (`curl ... <adresse>`) | hoch: Angreifer-Infrastruktur |
| `injection_source` | Logon-Request zur Versuchszeit im Access-Log | hoch; bei NAT nur die NAT-Adresse |
| `dropper_requester` | Requests auf nsgclient-Pfade, mit Anzahl | prüfen: echte Linux-Clients fragen dieselben Pfade |
| `outbound_hit` | aktive Verbindung zu bekannter Angreifer-Adresse | hoch |

Dazu führt das Script je Appliance die kumulierte Liste `ns_quickcheck_observed_ips.tsv` im selben Verzeichnis, je Lauf fortgeschrieben, ohne Löschung durch die Report-Retention: elf Spalten: `kategorie`, `adresse`, `anzahl_zuletzt` (Treffer des letzten Laufs), `zuletzt_fenster_h`, `anzahl_max`, `max_fenster_h`, `tage` (Kalendertage mit Beobachtung, mehrere Läufe am Tag zählen einmal), `zuerst_gesehen`, `zuletzt_gesehen`, `beobachtung`, `gesperrt` (Bemerkung und Datum aus der Sperrliste; intern, vor Weitergabe entfernen). Keine Summe: Jeder Lauf liest dieselben Logs erneut. Dieselbe Adresse kann in zwei Kategorien stehen, das sind zwei Rollen. Die Terminalzeile "Adressliste dieses Laufs: n Einträge, davon m neu gegenüber dem Bestand" ist die Zeile, auf die ein Admin reagiert: eine Adresse, die seit Wochen täglich Dropper-Pfade abfragt, ist ein anderer Befund als eine, die heute zum ersten Mal auftaucht.

**Anonymisierte Fassungen und Share-Datei.** Je Lauf entstehen zusätzlich `..._ips_anon.tsv` und `ns_quickcheck_observed_ips_anon.tsv` (ohne Hostname, Bemerkungen der Sperr- und Vertrauensliste entfernt, Zuordnungstabelle angewandt; weitergabefähig wie der anon-Report) sowie `..._share.tsv`: die kumulierte Liste reduziert auf die belastbaren Kategorien (`payload_download_host`, `injection_source`, `webshell_hit`, `outbound_hit`, `aaa_bruteforce`, `aaa_maschine`, `aaa_hit`, `ssh_bruteforce`, `dropper_requester` ab 3 Treffern) mit Spalten `kategorie`, `ip`, `zuerst`, `zuletzt`, `tage`, `anzahl_max`, `max_fenster_h`, `anzahl_zuletzt`, `regeldatei`; keine Appliance-Kennung, keine Bemerkungen, keine `trusted_*`- oder Sondierungs-Einträge. Die Share-Datei ist für die Weitergabe an ceterion gedacht (nach Durchsicht, bewusst, per Mail an die Kontaktadresse); daraus entsteht ein bestätigter Adress-Feed, in den eine Adresse erst nach Meldung von zwei unabhängigen Appliances aufgenommen wird.

Für den Firewall-Import: `grep -v '^#' ns_quickcheck_observed_ips.tsv | cut -f2 | sort -u` liefert die reine Adressliste.

Eigene und RFC-1918-Adressen stehen nie darin. Vor einer Blockliste prüfen: geteilte Infrastruktur (CDN, Cloudflare WARP, Proxies, NAT) blockt Unbeteiligte mit. Die Liste enthält, was beobachtet wurde, nicht die Indikatoren der Regeldatei; wer die ganze Regeldatei als Blockliste will, zieht sie aus dem IOC-Abschnitt.

### 5.3 Anonymisierung

| Thema | Inhalt |
|---|---|
| Was ersetzt wird | Adressen aus `ns.conf` (NSIP, SNIP, vServer, Server, HA-Peer, Auth-Server) und jede RFC-1918-Adresse im Text; Hostname und HA-Peer; System-User außer `nsroot` und bekannten Backdoor-Konten; Auth-Server-Namen, FQDNs aus Server-Objekten und Monitoren, DNS-Suffixe, E-Mail-Adressen; Objektnamen aus `ns.conf` (vServer, Policies, Actions, Profile, Server, Zertifikate, Themes) ab vier Zeichen, Zertifikats- und Schlüsseldateinamen, DN-Komponenten aus `bindDn` und `ldapBase`; Theme-Verzeichnisse außerhalb der Stock-Themes |
| Was maskiert wird (ohne Tabelle, immer `***`) | Werte hinter Secret-Parametern (`-password`, `-ldapBindDnPassword`, `-radKey`, `-tacacsSecret`, `-secret`, `-sharedSecret`, `-clientSecret`, `-pskKey`, `-community`, `-tsigKey`, `-passplain`), Passwort-Hashes von System-Usern, SNMP-Communities, verschlüsselte Blöcke vor `-encrypted`. Kommentarzeilen einer `ns.conf` werden zu "# (Kommentar entfernt)" |
| Womit | stabil je Appliance: Adressen `198.51.100.n` (ab 255 `203.0.113.n`), Hosts `gw-01`, `gw-02`, User `user01`, Domains `example1.net`, Mail `user1@example.net`, Objekte `obj001`, Themes `theme01` |
| Was bleibt | Angreifer-Adressen und -Domains, Hashes, Pfade, Zeitstempel, Build, Regelstände, SHA-256, Backdoor-Kontonamen |
| Zuordnungstabelle | `ns_quickcheck.anon.<host>.map` neben der Regeldatei, je Appliance eine (bei Hostname `gw-frankfurt` heißt sie `ns_quickcheck.anon.gw-frankfurt.map`); Rechte 600; wächst mit jedem Lauf, Ersatznamen ändern sich nie; bleibt auf der Appliance, geht nie ins Snapshot-Set, nie ins Repo, nie an Dritte. Löschen heißt neue Ersatznamen beim nächsten Lauf; alte und neue anon-Reports sind dann nicht mehr vergleichbar |
| Dateinamen | anon-Reports tragen den Ersatzhost: `ns_quickcheck_gw-01_<zeit>_anon.txt`; der echte Host steht nur im Original und im Tabellennamen |
| `--anon <datei>` | beliebiger Logauszug oder eine `ns.conf` mit derselben Tabelle, für Issues, Support-Fälle und den Recherche-Prompt: `sh ns_quickcheck.sh --anon /var/log/ns.log.1 > /var/tmp/ns.log.1.anon`, `sh ns_quickcheck.sh --anon /nsconfig/ns.conf > /var/tmp/ns.conf.anon`; auf stderr steht, wie viele Zuordnungen und Geheimnisse ersetzt wurden |
| Grenzen | erkennt nur, was in `ns.conf` steht oder privat ist. Fremde Hostnamen, AD-Benutzernamen in Logon-Zeilen, öffentliche Kunden-IPs in Logzeilen und Freitext in Policy-Expressions (`HTTP.REQ.URL.CONTAINS("kunde")`) bleiben Klartext. Deshalb steht "Stichprobe vor Weitergabe" im Kopf jeder anon-Datei |
| Lesehilfe | ein anon-Report liest sich wie das Original; `obj001` in einer Responder-Zeile ist die Policy, `theme01` das eigene Theme. Wer die Zuordnung braucht, hat das Original |

### 5.4 Sperrliste des Betreibers

`ns_quickcheck.blocked_ips` neben dem Script (Vorlage `ns_quickcheck.blocked_ips.example`, 600, bleibt beim Update, nie verteilt): was Firewall, Blocklist-Feed oder Appliance bereits sperren. Zeile: `adresse_oder_netz ; seit ; Bemerkung`; Pflicht ist nur die Adresse, ohne Datum ist sie nur markiert. Übergangene Zeilen (keine gültige IPv4-Adresse oder kein Netz) nennt die Kopfzeile mit Zeilennummer. ACLs der Appliance (`add ns simpleacl` und `add ns acl` mit DENY) gelten automatisch als gesperrt, ohne Datum.

**Aufbau der Datei**

Eine Zeile je Adresse oder Netz, Felder mit Semikolon getrennt (Leerzeichen egal, Tabs erlaubt), Kommentare mit `#`:

```
# adresse_oder_netz ; seit ; Bemerkung
203.0.113.44    ; 2026-10-20 ; fw-zentral, INC-4711, Download-Host Injection 19.10.
192.0.2.0/24    ; 2026-10-21 ; fw-zentral, INC-4711, Dropper-Suche, ganzer Bereich
203.0.113.126   ; 2026-10-21 ; Access-Portal Blacklist (FW)
203.0.113.9     ;            ; blocklist des SOC, Datum unbekannt: nur markiert
```

| Feld | Pflicht | Inhalt | Erscheint in |
|---|---|---|---|
| 1 Adresse oder Netz | ja | IPv4 oder CIDR (`/24`); IPv6 nicht | Befundzeilen, anon-Report, Adresslisten |
| 2 seit | für ORANGE | `YYYY-MM-DD`, Tag, ab dem die Sperre wirkt; leer = nur markiert | Befundzeilen ("Sperre ab 2026-10-21"), anon-Report, Adresslisten |
| 3 Bemerkung | nein | intern: wo die Sperre sitzt, Ticket, Kollege, Grund | Original-Report (`[Bemerkung: ...]`) und Adresslisten, nie anon-Fassungen |

Befundtext: `203.0.113.126: Sperre ab 2026-10-21 [Bemerkung: ...], letzte Beobachtung 2026-10-20, 12 Request(s)`; in der anon-Fassung ohne den Bemerkungsteil. Zeilen ohne gültige IPv4-Adresse nennt die Kopfzeile mit Zeilennummer, Zeilen ohne Datum zählt sie ("n ohne Datum: nur markiert"). ACLs der Appliance (`add ns simpleacl`, `add ns acl` mit DENY) werden automatisch als gesperrt ohne Datum ergänzt. Pflege: das Datum der Firewall eintragen, nicht das des Reports; eine aufgehobene Sperre heißt Zeile löschen. Lässt sich das Datum einer Beobachtung nicht bestimmen (Logzeile ohne lesbaren Zeitstempel), sagt der Report das und bewertet wie ungesperrt.

Wirkung, als vierte Stufe ORANGE "abgedeckt":

| Befund | gesperrt, Beobachtung vor dem Sperrdatum | gesperrt, Beobachtung danach | nicht gesperrt |
|---|---|---|---|
| Injection-Versuch mit Download-Host | ORANGE | ROT | ROT |
| Dropper-Anfragen, Dropper-Suche | ORANGE je Adresse ("abgedeckt", mit Zu tun: nichts) | GELB "Sperre greift nicht" mit Anzahl und letztem Datum | GELB oder ROT |
| aktive Verbindung zu Angreifer-Adresse | ROT | ROT | ROT |
| Payload-Datei, Webshell, Backdoor-Konto | ROT (eine Sperre ändert nichts daran, was auf der Appliance liegt) | ROT | ROT |

Orange zählt nicht als Spur und nicht als Kompromittierungszeichen. Bleiben nur Orange-Befunde, lautet das Verdict `OK` mit dem Hinweis, dass der nächste Lauf prüft, ob die Sperren halten. Ohne Datum (ACL der Appliance, leeres Feld) wird eine Adresse nur markiert ("gesperrt, Datum unbekannt: nur markiert"), nicht abgedeckt. Adresslisten bekommen die Spalte `gesperrt` (`bemerkung|seit`, intern, vor Weitergabe entfernen), RESULT die Felder `orange=` und `blocked_seen=`, das JSON die Liste `orange` und je Adresse `blocked`.

Das Script setzt keine Sperre und prüft nicht, ob die Firewall-Regel existiert; die Datei dokumentiert, was der Betreiber sagt, und das Access-Log zeigt, ob es stimmt.

### 5.5 Vertrauensliste: Adressen, deren Verhalten gewollt ist

`ns_quickcheck.trusted_ips` neben dem Script (Vorlage `ns_quickcheck.trusted_ips.example`, 600, bleibt beim Update, nie verteilt): Schwachstellenscanner, Pentester im Auftragsfenster, Monitoring, Partner-Gateways, Admin-Netze. Zeile `adresse_oder_netz ; bis ; Bemerkung`; `bis` ist ein Ablaufdatum (`YYYY-MM-DD`, leer = unbefristet), abgelaufene Einträge werden übergangen und in der Kopfzeile gezählt. Steht eine Adresse auch in der Sperrliste, meldet die Kopfzeile WARN, die Sperrliste gilt.

Wirkung je Befundart:

| Befundart | vertraute Adresse |
|---|---|
| Management-Zugriffe, SSH-Logins, Webserver direkt, Anmeldefehler eigener Adressen | wie intern, kein Gelb |
| Sondierung, Dropper-Anfragen, Spraying, Brute Force, Schläfer | aus dem Gelb-Befund herausgenommen; der Befund bleibt für die übrigen Adressen |
| Injection-Zeile, Webshell-Pfad mit 200, Erfolg nach Fehlserie, aktive Verbindung | **bleibt Rot**, mit Zusatz "Adresse in trusted_ips" |

Alles, was eine vertraute Adresse im Fenster getan hat, steht gesammelt in einem `[TRUST]`-Block (blau, ohne Verdict-Wirkung; `TRUST_LEVEL=yellow` macht Gelb daraus) mit der Frage, ob der Eintrag richtig und noch gewollt ist. Stand die Adresse laut kumulierter Adressliste vorher als Angreifer (etwa `dropper_requester`), erscheint einmalig eine Gelb-Zeile, damit ein Tippfehler auffällt. In den Adresslisten tragen vertraute Adressen die Kategorie `trusted_<art>`; der Import-Befehl im Dateikopf schließt sie aus. `trusted_seen=` in RESULT, Liste `trust` im JSON. Die Bemerkung steht nur im Original-Report.

## 6. Die sechs Blöcke

Detaillisten (Logzeilen, Pfade, Adressen, Sessions) stehen vollständig in Terminal und Report; `DETAIL_MAX` in der Config begrenzt sie bei Bedarf, dann steht "... und n weitere" darunter. Jeder Befund (Rot, Gelb, Orange) hat Detailzeilen mit festen Beschriftungen: "Wann", "Log" (Datei und Trefferzahl), "Ergebnis", "Download-Host" oder "Adresse" (je Adresse Sperrliste, Regeldatei, Adressliste), "Quelle", "Netze" (Quellen je /24 zusammengefasst), "Zu tun" (nummeriert). Logzeilen sind auf `LINE_MAX` Zeichen gekürzt (Vorgabe 400, 0 = ungekürzt); Injection-Zeilen immer vollständig. Die Kopfzeile nennt den Fachbegriff, die Detailzeilen beantworten die vier Fragen wann, was, woher, was tun. Vor der RESULT-Zeile steht die Liste der Adressen dieses Laufs mit Status gegenüber dem Bestand (neu oder bekannt seit, Anzahl Tage; mehrere Läufe am selben Tag zählen einmal) und Sperrliste.

### Block 1 Build

| Prüfung | Quelle | Bewertung |
|---|---|---|
| laufender Build gegen jede Zeile der `CVE_TABLE` (Bedingung `all`, `conf:<regex>` nur bei Treffer in `ns.conf`, `tcpparam:`) | `kern.bootfile` online, `meta.tsv` offline, Fallback `ns.conf`-Header | Rot "VERWUNDBAR" je offener CVE mit Ziel-Build; OK, wenn alle Fixes enthalten |
| Zeilen aus der Custom-Datei | CVE-Block der Custom-Datei, markiert `[custom]` | wie oben; weicht die Regeldatei ab, erscheinen beide Zeilen, das strengere Ergebnis zählt |
| End-of-Life-Train (`EOL_RELEASES`) | Regeldatei | Rot, kein Fix verfügbar |
| gespeicherte Config vs. laufend | `ns.conf`-Header | Gelb: `save ns config` fehlt |
| bekannt problematischer Build | `BUILD_WARN_*` | Gelb |
| gestagter Build | `/flash/ns-*.gz` jünger als Boot | Gelb: Reboot ausstehend |

### Block 2 Exposure

| Prüfung | Bewertung |
|---|---|
| SAML SP oder IdP | Info; die SAML-CVEs werden in Block 1 über die Bedingung bewertet |
| DTLS an Gateway-vServern | Info, auf gefixtem Build mitigiert |
| Konfigurationsschritte (`tcpparam:`-Zeilen, heute Enhanced ISN Generation) | Gelb, wenn der Parameter fehlt; bleibt nach dem Upgrade offen |
| Admin-Partitions | Info, dort separat prüfen |
| Management-Zugriff auf SNIP | Gelb (NITRO erreichbar) |

### Block 3 Mitigation

Findet Responder- und Traffic-Policies, deren Regel ein Muster aus `MITIGATION_RULE_RE` enthält. Policy vorhanden, nicht gebunden: Gelb. Gebunden, Feature aus: Gelb. Gebunden, nicht `AAA_REQUEST`: Gelb. Korrekt gebunden: OK mit Hit-Counter und Delta zum letzten Lauf. Keine Policy: Gelb auf offenem Build, sonst Info.

### Block 4 Angriffsspuren

Logdateien werden nach Änderungszeit ausgewählt (`--hours`); die Kopfzeile des Blocks nennt die gelesenen Familien und Dateizahlen. Admin-Befehle (`CMD_EXECUTED`) sind ausgeschlossen. Fehlt eine Familie oder eine Regel dafür, steht eine INFO "nicht geprüft" mit dem Grund. Die Prüfungen in vier Gruppen:

**4a Spuren der Bulletin-CVEs**

| Prüfung | Bewertung |
|---|---|
| Injection-Muster in Logon-Zeilen (`ns.log`, `nsvpn.log`, `messages`, `notice.log`) | Rot mit Zeitraum, Zeilen vollständig, Download-Hosts aus dem Payload mit Sperrliste, Regeldatei und Adressliste; auf gefixtem Build "Versuch ohne Wirkung", mit gesperrtem Download-Host Orange |
| Quelle des Versuchs | bei Logon-Zeilen: Logon-Requests im Access-Log zur Versuchszeit mit Offset-Suche, ausgewiesen als "passt zu n von m Versuchszeiten", "schwach" bei einem Treffer von mehreren; bei Responder-Zeilen: aus der Zeile selbst (`from IP`, `Client_ip`, `CLIENT.IP.SRC`), weil der Request den Webserver nie erreichte; sonst "unbekannt" mit Grund |
| nsaaad-Crash-Zeilen und Core-Dumps | Rot bei SAML auf ungefixtem Build, sonst Gelb |
| DTLS-Handshake-Fehler plus Packet-Engine-Neustart | Rot |
| Requests auf Dropper-Pfade je Quell-IP | Gelb mit Adressen, Pfaden, Netzen; Rot "Dropper-Suche, kein Client" (mehr als zwei Paketnamen oder Kommandozeichen im Query-String, oder Quell-IP mit Injection-Zeile); gesperrte Adressen Orange oder "Sperre greift nicht" |

**4b Webserver**

| Prüfung | Bewertung |
|---|---|
| Interpreter-Fehler außerhalb der Verwaltungsoberfläche (`httperror*`, `HTTPERR_EXEC_RE`) | Rot: PHP oder CGI haben außerhalb von admin_ui gearbeitet |
| Webshell-Pfad mit Status 200 im Access-Log | Rot, Kompromittierungszeichen; Adressliste `webshell_hit` |
| Webshell-Sondierung: "File does not exist" für Webshell-Namen, PHP-Varianten, Scanner-Pfade und die Dateinamen aus `PAYLOAD_PATHS` (`HTTPERR_PROBE_RE`) | Gelb "Versuch ohne Wirkung" mit Pfaden, Zeitraum, Quellen aus dem Access-Log, Netzen, Sperrstatus; Adressliste `webshell_probe`; `PROBE_LEVEL=info` macht daraus INFO. Hinweis im Block: `[client 127.0.0.2]` ist die Appliance selbst (Glossar) |
| Client im Fehlerlog außerhalb 127.0.0.x | Gelb "Webserver direkt angesprochen"; Adressliste `webserver_direct` |
| PHP-Speicher-/Fatal-Muster im Management-Portal, auch `admin_ui` (`HTTPERR_PHP_ANOMALY_RE`, CTX697263) | ab `PHP_ANOMALY_MIN` Zeilen: INFO auf gefixtem Build, Gelb auf verwundbarem; Rot in Block 5, wenn dazu eine neue PHP-Datei im Fenster liegt. Heuristik, keine Signatur |

**4c Management und SSH**

| Prüfung | Bewertung |
|---|---|
| NITRO- und GUI-Requests (`httpaccess.log` der NSIP, `MGMT_PATH_RE`) von Adressen außerhalb RFC 1918 und `MGMT_NET_RE` | Gelb mit Adressen; Adressliste `mgmt_access` |
| SSH- und Konsolenanmeldungen (`auth.log`): Logins von außen, Backdoor-Konten, Fehlversuche in Serie ab 10 je Adresse | Gelb; Rot bei Anmeldung eines bekannten Backdoor-Kontos; Adresslisten `ssh_login_external`, `ssh_bruteforce`; sonst INFO mit den Anmeldungen (ohne `#nsinternal#`) |

**4d Gateway-Konten (AAA, `ns.log`)** in dieser Reihenfolge:

| Befund | Definition | Bewertung |
|---|---|---|
| Treffer | Erfolg nach Fehlserie einer Maschine (gleiche Adresse, gleiches Konto, innerhalb `AAA_OK_WIN`) oder nach Brute Force auf ein Konto (von jeder Adresse) | **Rot**, Kompromittierungszeichen; Adressliste `aaa_hit`; Konto sperren, Passwort zurücksetzen, `kill aaa session -userName`, MFA prüfen; "ein Mensch muss das entscheiden" |
| Brute Force | ein Konto mit mindestens `AAA_BF_MIN` Fehlversuchen oder `AAA_RATE`/min, von beliebig vielen Adressen | Gelb mit Konto, Fehlversuchen, Adressen, Zeitraum, Takt; Adressliste `aaa_bruteforce`; Howto Lockout |
| Schläfer | Adresse mit mehreren Konten, keinem Erfolg, unter Maschinen-Takt, Versuche an mindestens `AAA_SLEEPER_DAYS` Tagen oder über diese Spanne (Fenster oder kumulierte Adressliste) | Gelb "langsames Spraying über Tage"; Adressliste `aaa_sleeper`; sperren |
| Password Spraying | je Adresse ab `AAA_FAIL_IP` Fehlversuchen oder `AAA_FAIL_USERS` Konten eine Zeile mit Fehlversuchen, Konten, Zeitraum, Takt, "Erfolg danach" und Bewertung: Maschine (Takt, Konten oder /24 mit mindestens zwei Maschinen), Nutzer (Erfolg danach), unklar (Mensch-Takt ohne Erfolg; ein Konto in kurzem Burst wird als wahrscheinlicher Client mit altem Passwort benannt) | Gelb; Netze oben; Reihenfolge unklar (höchstens 10), Maschinen (höchstens 10), Nutzer als Zahl; angegriffene Konten mit Anzahl; Zahl der Konten, die nur einmal vorkommen; Adressliste `aaa_bruteforce` für Maschinen |
| Eigene oder interne Adressen | Fehlversuche von `ns.conf`-Adressen (mit Objektname), RFC 1918 oder `MGMT_NET_RE` | Gelb, eigener Befund: Dienstkonto, Monitoring, Admin-Test, NAT-Ausgang oder interner Host; nie in Adresslisten; Erfolg nach Fehlserie Rot |

Kontonamen stehen im Original-Report (`[Bemerkung: Konten ...]` und Kontenliste); die anon-Fassung maskiert sie über die Zuordnungstabelle.

### Block 5 Kompromittierungs-Schnellcheck

| Prüfung | Bewertung |
|---|---|
| bekannte Payload-Pfade (IOC `path` aus Regeldatei und Custom) | Rot, mit Quelle und Datum des Indikators |
| Webshell-Dateinamen und PHP außerhalb der Stock-Verzeichnisse | Rot |
| Web-Dateien seit Boot geändert (außerhalb Upgrade-Fenster: 15 min nach Boot und 30 min nach dem letzten Upgrade laut `nsinstall.log`) | Gelb, Burst ab 5 Dateien in 30 s als "Rewrite"; Erklärzeile: Theme-Anpassung typisch, `.php` oder Pfade außerhalb des Themes melden; Whitelist `webfile:` |
| `httpd.conf` nicht zur Boot-Zeit geändert | Gelb, wenn der Inhalt unauffällig ist (Zeitstempel allein); Rot bei Alias außerhalb `STOCK_ALIAS_ROOTS` oder PHP-Handler in `/vpns`, `/logon`, `/epa` |
| Root-Crontab außerhalb `ALLOWED_CRON_RE`; Crontab für `nobody` | Gelb; Rot |
| Listener von Interpreter- und Shell-Prozessen | Stock (`KNOWN_LISTENER_RE`) kein Befund; unbekannt auf Loopback Gelb, sonst Rot; Whitelist `listener:` |
| aktive Verbindung zu Download-Host oder Angreifer-Adresse (IOC `ip`, `dom`) | Rot |
| Änderungen `ns.conf.0` zu `ns.conf` an sicherheitsrelevanten Objekten; ungespeicherte Zeilen (CLI-Ebene) | Gelb; Rot bei User-, Auth- oder Policy-Zeilen |
| `--compare`: Web-Dateien, System-User, Listener neu seit dem Snapshot | Gelb; Rot bei neuen Usern |
| lokale System-User neben `nsroot`, Service-User und Whitelist `user:` | Gelb; bekannte Backdoor-Konten Rot |
| verdächtige Prozesse (`SUSPECT_PROC_RE`) mit Parent-Prüfung; Stock-Hash von `ns_monuploadd_err.pl` | Info bei Stock-Parent, sonst Rot; Rot bei Hash-Abweichung |
| EPA-Default `NO_AUTH`; `/bin/sh` setuid | Rot |

Fehlalarme (eigenes Monitoring, Theme-Edits, dienstliche Konten) nimmt `ns_quickcheck.whitelist` je Appliance aus: eine Regel je Zeile `<typ>:<regex>`, Typen `user`, `listener`, `path`, `cron`, `webfile`.

### Block 6 Verdict

Abschnitt 7.

## 7. Verdict: was es heißt und was jetzt zu tun ist

| Verdict | Exit | Das heißt | Jetzt tun | Dann | Wer informiert wird |
|---|---|---|---|---|---|
| `OK` | 0 | Build gefixt, keine Spuren, nichts Offenes; Orange-Befunde (durch Sperren abgedeckt) dürfen bleiben | nichts; bei Orange den nächsten Lauf abwarten, der zeigt, ob die Sperren halten | nächster Lauf nach dem nächsten Bulletin oder per Cron | niemand |
| `INVESTIGATE` | 1 | Build gefixt, keine Kompromittierungszeichen, aber Beobachtungen, die jemand einordnen muss (Versuch geblockt, Dropper-Anfragen, geänderte Dateien) | die "Zu tun"-Zeilen abarbeiten: Access-Log, Firewall-Log, Ticket zur Theme-Änderung; Adressliste an Firewall/SOC | Lauf wiederholen; sind die Punkte geklärt oder in der Whitelist, wird es `OK` | Sicherheitsbeauftragter bei Versuchen mit Download-Host |
| `UPDATE` | 2 | Build offen oder End-of-Life, keine Spuren | zuerst sichern (`show techsupport`, `/var/log` extern), dann patchen auf den Ziel-Build aus Block 1; HA: Secondary zuerst | nach dem Upgrade `save ns config`, Enhanced ISN setzen, Lauf wiederholen | Change-Verantwortlicher |
| `FORENSICS_FIRST` | 2 | Kompromittierungszeichen: Payload-Datei, Webshell, Backdoor-Konto, aktive Verbindung zu Angreifer-Adresse, nsaaad-Crash bei offener SAML-CVE | nicht patchen, nicht neu starten: das Upgrade überschreibt Spuren. Appliance isolieren (Gateway-vServer disable), Incident-Prozess starten | Forensik entscheidet; danach Neuaufbau oder Upgrade | Geschäftsführung, Sicherheitsbeauftragter, bei Bedarf Behörde |

### 7.1 RESULT-Zeile

`RESULT host=... build=... mode=online|offline cli=... window=<h>h saml=0|1 vuln96=0|1 vuln79=0|1 isn_open=0|1 traces=0|1 mitigation=0|1 unsaved=0|1 save_missing=0|1 compromise=0|1 red=<n> yellow=<n> orange=<n> blocked_seen=<n> coverage=full|partial action=<Verdict> rules=<Regelstand> script_sha256=... rules_sha256=... custom=<Version|none> custom_sha256=... cve_custom=<n> cve_conflict=<n> runtime=<s>s`

`coverage`: `full`, oder `partial`, wenn eine Kernprüfung ohne Daten blieb (ns.log- oder httpaccess-Familie fehlt im Fenster, Datei nicht lesbar); bei `partial` wird das Verdict nie `OK`. `vuln96`: eine CVE aus CTX697096 offen (seit 17.38 nur dieses Bulletin). `vuln_open`: Zahl offener CVE-Zeilen über alle Bulletins. `vuln63`: eine CVE aus CTX697263 (PHP2Shell) offen. `vuln79`: mindestens eine SAML-abhängige CVE offen. `cve_conflict`: Regeldatei und Custom-Datei bewerten eine CVE unterschiedlich.

Zwei Regeln über den Befunden: `coverage=partial` (siehe oben) macht das Verdict nie `OK`; Orange-Befunde (durch Sperren abgedeckt) zählen nicht als Spur, ein Lauf mit nur Orange ist `OK`.

### 7.2 JSON

```
{ "script": "ns_quickcheck", "version": "17.43", "host": "...", "ts": "...",
  "result": { ...alle RESULT-Felder... },
  "mitigation_hits": { "<policy>": "<hits>" },
  "observed_ips": [ { "category": "dropper_requester", "ip": "...", "count": 24, "observed_in": "httpaccess DROPPER_PATH_RE", "blocked": "fw-zentral|2026-10-21" } ],
  "red":    [ { "text": "...", "details": [ "..." ] } ],
  "yellow": [ { "text": "...", "details": [ "..." ] } ],
  "orange": [ { "text": "...", "details": [ "..." ] } ] }
```
URLs sind defanged (`hxxp`); Adressen stehen unmaskiert. Das JSON ist für Ticketsysteme und den Collector; nach außen geht die `_anon.json`.

## 8. Regeldatei, Custom-Datei, Herkunft

### 8.1 Regeldatei Format 2

Die Regeldatei enthält Prüfmuster (Regex-Variablen), die `CVE_TABLE` (eine Zeile je CVE, Train und Bedingung) und den IOC-Abschnitt: je Indikator eine Zeile mit Typ, Wert, Quelle, Veröffentlichungsdatum, Klasse, Fundstelle beim Erstautor und Regelstand der Aufnahme. Verbindliche Beschreibung: `docs/rules-format-2.md`. Pflege durch ceterion; Betreiber ändern die Datei nicht (8.4).

Regelvariablen, die das Script erwartet (fehlt eine Kernvariable, Exit 3; fehlt eine jüngere, entfällt die Prüfung mit INFO und die Kopfzeile nennt den Mindeststand `RULES_MIN`):

| Gruppe | Variablen |
|---|---|
| Kern (Pflicht) | `RULES_VERSION`, `TRIGGER_RE`, `OBFUSC_RE`, `CMD_NAMES`, `LOGON_HINT_RE`, `ADMIN_CMD_RE`, `CVE_TABLE` |
| Bulletin-Spuren | `NSAAAD_CRASH_RE`, `DTLS_FAIL_RE`, `PPE_CRASH_RE`, `LOGIN_PATH_RE`, `DROPPER_PATH_RE`, `MITIGATION_RULE_RE`, `EOL_RELEASES`, `BUILD_WARN_*` |
| Block 5 | `PAYLOAD_PATHS`, `STOCK_ALIAS_ROOTS`, `ALLOWED_CRON_RE`, `KNOWN_LISTENER_RE`, `SUSPECT_PROC_RE`, `SUSPECT_PROC_PARENT_OK_RE`, `STOCK_FILE_HASHES` |
| seit 2026-10-21 (Logs) | `HTTPERR_EXEC_RE`, `HTTPERR_PROBE_RE`, `AUTH_LOGIN_RE`, `AUTH_FAIL_RE`, `MGMT_PATH_RE` |
| seit 2026-10-21c/d (AAA) | `AAA_FAIL_RE`, `AAA_OK_RE` |
| seit 2026-10-23 (CTX697263) | `HTTPERR_PHP_ANOMALY_RE`, `MGMT_ACL_RE` |
| seit 2026-10-27 (Abstürze) | `PITBOSS_RE`, `KERNEL_EXIT_RE`, `NSAAAD_CRASH_LEGACY_RE` |
| seit 2026-10-28d (weitere Belege) | `HTTPERR_CRASH_RE`, `KERNEL_MEM_RE`, `KERNEL_PANIC_RE` |
| IOC-Abschnitt | Zeilen `ip`, `dom`, `hash`, `path`; daraus baut das Script `ATTACKER_IP_RE`, `ATTACKER_DOM_RE` (mit Grenzen, ohne Groß-/Kleinschreibung) und die Pfad- und Hashlisten |

### 8.2 Herkunftsprotokoll

| Thema | Inhalt |
|---|---|
| Dateien | `ns_quickcheck.rules.provenance.csv` (Semikolon, für Tabellenkalkulation und Collector) und `.md` (lesbar), im Repo neben der Regeldatei |
| Entstehung | `docs/provenance.sh` erzeugt sie aus der Regeldatei, bei jedem Release neu; nie von Hand gepflegt, nie älter als die Regeldatei |
| Inhalt | je Indikator: Typ, Wert, Quelle, Veröffentlichungsdatum beim Erstautor, Fundstelle, Status, Regelstand; je CVE-Zeile: CVE, Train, Fix-Build, Bulletin-URL |
| Zweck | die Antwort auf "woher kommt dieser Wert" in einer Zeile; Grundlage für CREDITS.md; Nachweis, dass kein Wert ohne Erstautor verteilt wird |
| Stand | 151 Zeilen, alle belegt (111 Indikatoren, 40 CVE-Zeilen). Unbelegte Werte stehen nicht in der Regeldatei |
| Custom-Datei | nicht enthalten; `sh docs/provenance.sh ns_quickcheck.rules.custom` erzeugt dem Betreiber dasselbe für seine Datei |
| Grenze | das Datum ist das der Veröffentlichung, nicht das unseres Abrufs; der Abrufnachweis steht in den Recherche-Läufen (`research_<datum>.md`) des Betreiberordners |

### 8.3 Grundsätze der Regelpflege

- Zusammenstellungen Dritter (Community-Scanner, Sammelseiten) sind Verweise, keine Quellen; Fundstelle ist immer die Veröffentlichung des Erstautors. Werte ohne Erstautor bleiben inaktiv (`PRUEFEN`).
- Die Regeldatei wird nur erweitert, nie gekürzt; eine Entfernung braucht einen Changelog-Eintrag mit Begründung.
- Das Script prüft beim Start, dass die Kernvariablen der Regeldatei vorhanden sind (`RULES_VERSION`, `TRIGGER_RE`, `OBFUSC_RE`, `CMD_NAMES`, `LOGON_HINT_RE`, `ADMIN_CMD_RE`, `CVE_TABLE`); fehlt eine, bricht es mit Exit 3 ab, statt mit leeren Mustern zu laufen.
- Jeder Regelstand durchläuft `docs/release.sh`: Plattform-Lints 1 bis 3, Format-2-Lint, Präfix-Prüfung, 69 Testlogs, 10 Fixtures, Herkunftsprotokoll.
- Regex: POSIX ERE ohne GNU-Erweiterungen, Semantik immer "Zeile passt ja/nein" (`rules-format-2.md`).

### 8.4 Custom-Datei des Betreibers

`ns_quickcheck.rules.custom` neben der Regeldatei, Vorlage `ns_quickcheck.rules.custom.example`. Zwei Blöcke: IOC (eigene Indikatoren, gleiche Spalten wie die Regeldatei) und CVE (eigene Fix-Build-Zeilen im `CVE_TABLE`-Format, etwa für ein Bulletin, das ceterion noch nicht nachgezogen hat). Beide werden zusätzlich geprüft; bei abweichendem Fix-Build zeigt Block 1 beide Zeilen, das strengere Ergebnis zählt. Eine Custom-Zeile kann ein Gerät nie grüner machen als die Regeldatei. Die Datei bleibt beim Update, wird nie verteilt und nimmt nur auf, was der Betreiber nutzen darf. Ablauf: WORKFLOW.de.md.

### 8.5 Patch anwenden

`sh docs/rules-apply.sh <ziel> <patch>` sichert das Ziel als `<ziel>.bak_<stand>`, prüft jede neue Zeile (Format, Fundstelle, Dubletten, bei CVE-Zeilen Abweichung zur Regeldatei) und aktualisiert das Ziel an Ort und Stelle. Ziel ist beim Betreiber die Custom-Datei, bei ceterion die Regeldatei. Form mit drei Argumenten (`<alt> <neu> <patch>`) für Tests.

### 8.6 Prompts

`ns_quickcheck_research_prompt.md` (Recherche: neue Bulletins, Berichte, Fundstellenprüfung) und `ns_quickcheck_rules_prompt.md` (Regel: aus Bulletin oder Bericht einen Patch). Zwei getrennte Chats, Ergebnisse werden geprüft, nie ungeprüft übernommen. Bedienung in WORKFLOW.de.md.

### 8.7 Verhältnis zu Community-Checkern

Community-Werkzeuge prüfen dieselben Bulletins mit eigenen Indikatorsammlungen. Der Quickcheck übernimmt aus ihnen keine Werte, sondern nur aus den Erstveröffentlichungen mit Fundstelle (Abschnitt 8.2); die Projekte sind getrennt. Wer die breiteste Abdeckung will, lässt mehrere Werkzeuge laufen und vergleicht die Befunde.

## 9. Validierungsstand und Abnahme-Protokoll

**Validiert:** NetScaler 14.1-73.41, 73.46 und 73.49 (MPX, Lab und Kundengateway): Online-Läufe mit `--compare cron`, Offline-Läufe gegen Snapshot-Sets und Fixtures, Custom-Datei, Sperrliste, Anonymisierung; am 21.10.2026 elf Lab-Läufe auf einem exponierten Gateway mit laufender Spraying-Kampagne (1.700 Anmeldefehler, 60 Maschinen-Adressen, Webshell-Sondierungen, Injection-Versuch), aus denen die Befundblöcke und Schwellen stammen. Testbasis: 69 Testlogs, 10 Fixtures, drei Plattform-Lints. **Beta:** 13.1, 13.1-FIPS, 14.1-FIPS und 14.1-Appliances mit Features, die das Lab nicht hatte (SAML, AppFW, Bot, GSLB, Admin-Partitions, Custom-Themes, Mitigation-Policies); beim ersten Lauf dort zwei bis fünf Fehlalarme erwartet.

**Abnahme auf jeder neuen Appliance vor der ersten Bewertung:**
1. Erster Lauf mit Trace: `sh -x ns_quickcheck.sh --no-out 2>/tmp/qc_trace.txt >/tmp/qc_out.txt; echo EXIT=$?`. Exit 139 heißt Absturz; `tail /tmp/qc_trace.txt` zeigt die Zeile; Issue mit Trace.
2. Ausgabe vollständig lesen. Jede rote und gelbe Zeile einordnen: Stock-Zustand des Builds, Betreiberkonfiguration oder Fund.
3. Stock-Zustände als Issue an ceterion (Regeldatei), Betreiberspezifisches in `ns_quickcheck.whitelist`.
4. Zweiter Lauf. Erst wenn jede verbleibende Zeile ein eingeordneter Fund ist, gilt das Verdict.
5. Protokoll ablegen: Trace, beide Reports (anon), Einordnung je Zeile, Hashes aus der RESULT-Zeile.

Budget: 15 Minuten je Appliance-Typ. Wer das überspringt, bekommt beim Betreiber ein `FORENSICS_FIRST` auf einer sauberen Appliance.

## 10. Sicherheitsbetrachtung: Was das Script auf dem System tut

**Rechte.** Läuft als `nsroot` in der Shell, weil Logs, `/nsconfig`, Prozessliste und Sockets nur root lesen darf. Es setzt keine eigenen Rechte, legt keine User an, ändert keine Dateien außerhalb seiner Ausgabeverzeichnisse.

**Liest.** `ns.conf`, `ns.conf.0`, `httpd.conf`, `/var/log/*` im Zeitfenster (auch `.gz`: `ns.log`, `nsvpn.log`, `messages`, `notice.log`, `httpaccess*`, `httperror*`, `auth.log`, `cron`), `/var/netscaler/logon`, `/var/vpn`, `/netscaler`, `/var/tmp`, `/tmp`, `/etc/crontab` und `/var/cron/tabs`, `/var/core`, `/flash/ns-*.gz`; Prozessliste (`ps`), Listener und Verbindungen (`sockstat`, `netstat`), `sysctl kern.bootfile`. Über die CLI-Ebene (optional) nur `show`-Befehle: `show ns runningConfig`, `show responder policy`, `show aaa session`, `show ns simpleacl`, `show ns version`.

**Schreibt.** Reports, JSON, Adresslisten und anon-Fassungen nach `/var/nssnapshot/quickcheck/` (600); die Zuordnungstabelle `ns_quickcheck.anon.<host>.map` neben die Regeldatei (600); Zwischendateien nach `/var/nssnapshot/tmp/qc.XXXXXX` (700), die beim Ende gelöscht werden, auch bei Abbruch. Sonst nichts: kein `save ns config`, kein `set`, kein `add`, kein Löschen von Betreiberdateien; die Retention löscht nur eigene Reports älter als `REPORT_KEEP_DAYS`.

**Führt aus.** Nur Bordmittel der Appliance: `sh`, `awk`, `grep`, `sed`, `perl`, `find`, `tar`, `gzip`, `sha256`, `ps`, `sockstat`, `netstat`, `sysctl`, `date`; keine nachgeladenen Programme, keine Pakete, kein `eval` von Dateiinhalten. Die Regeldatei wird gesourct; deshalb Rechteprüfung (nicht group/world-writable) vor dem Laden und ein Lint, der Shell-Konstrukte in ihr ablehnt. Die Custom-Datei wird nicht gesourct, nur zeilenweise gelesen.

**Netzwerk.** Keine ausgehende Verbindung, keine DNS-Abfrage, kein Upload. Das Script prüft Verbindungen, es baut keine auf.

**Zugangsdaten.** Die CLI-Ebene nutzt den Service-User aus `ns_snapshot.conf`, falls der Snapshot läuft, sonst aus `ns_quickcheck.conf` (beide root-owned, 600). Bekannte Schwäche: `nscli -U %%:user:passwort` übergibt das Passwort als Argument; es ist für die Dauer des Befehls (Sekunden) in der Prozessliste sichtbar. Deshalb ein eigener Service-User mit Read-only-Command-Policy, nie `nsroot`; `cli_script.sh` ohne Passwort, wo verfügbar. Reports enthalten keine Passwörter oder Hashes; der Config-Diff maskiert sie.

**Fußzeile.** Report und anon-Fassungen enden mit "Erstellt mit netscaler-quickcheck <Version> (Regelstand <Stand>), Apache 2.0, ceterion AG: ceterion.com/netscaler-quickcheck"; `FOOTER=0` in der Config schaltet sie ab, der Report bleibt vollständig.

**Daten in den Ausgaben.** Original-Report und JSON enthalten Hostnamen, interne Adressen, Objektnamen, Logzeilen mit Benutzernamen und seit 17.25 die Kontonamen aus Gateway-Anmeldefehlern (Personendaten): betreiberintern, Aufbewahrung nach eigener Regel, `REPORT_KEEP_DAYS` löscht nach 30 Tagen. Die anon-Fassungen ersetzen, was in `ns.conf` steht oder privat ist, nicht mehr. Nach außen nur anon, nach Stichprobe (5.3).

**Nachvollziehbarkeit.** Jede RESULT-Zeile trägt SHA-256 von Script, Regeldatei und Custom-Datei; der Betreiber kann prüfen, dass lief, was er freigegeben hat. Laufzeit 5 bis 30 Sekunden, kurze CPU-Last, keine Auswirkung auf den Datenverkehr; bei sehr großen Access-Logs begrenzt `ACCESS_LOG_MAX_MB` die Lesemenge.

**Was zu bedenken bleibt.** Ein Script, das als root läuft, ist Vertrauenssache: Hash gegen die Release-Seite prüfen, Datei 600, nicht aus einem beschreibbaren Ordner starten. Die Regeldatei ist Code (gesourct); nur aus dem Release oder nach eigener Prüfung einspielen. Die Custom-Datei ist kein Code, kann die Bewertung aber strenger machen; das ist beabsichtigt.

## 11. Runbook Problemfall

Hash-Prüfung gemeldeter Dateien: nur den SHA-256 bei VirusTotal nachschlagen, nie die Datei hochladen (öffentlich, enthält Betreiberdaten).

1. Quickcheck online mit `--compare cron`; Report und JSON in `/var/nssnapshot/quickcheck/`.
2. Verdict lesen (Abschnitt 7). `FORENSICS_FIRST` beendet den Patch-Plan, Incident-Prozess starten. Steht ein AAA-Treffer darin: zuerst das Konto sperren, Passwort zurücksetzen, `kill aaa session -userName <konto>`, dann weiter.
3. Bei `UPDATE`: sichern, dann patchen. Mindestens `show techsupport` und `/var/log` extern, bei Spuren auch `/var/core`.
4. HA-Paar: beide Knoten prüfen; HA-File-Sync kopiert Webshells.
5. Upgrade: Ziel-Build aus Block 1, Secondary zuerst, Failover, Primary. Danach `save ns config`, `set ns tcpParam -enhancedISNGeneration ENABLED` in jeder Partition, `save ns config -all`.
6. Nachlauf: Quickcheck wiederholen, Verdict `OK` oder `INVESTIGATE` ohne Rot. Adressliste an Firewall und SOC.
7. Zweite Meinung bei exponierter Appliance: der offizielle Citrix-IoC-Scan (Funktion "Indicators of Compromise" der NetScaler Console, https://docs.netscaler.com/en-us/netscaler-console-service/instance-advisory/ioc; ohne Console über ein Support-Ticket).
8. Ticket: `_anon.txt` und `_anon.json` anhängen, RESULT-Zeile in die Zusammenfassung, Regelstand nennen.

## 12. Grenzen und bekannte Schwächen

| Punkt | Auswirkung | Status |
|---|---|---|
| CLI-Ebene nur mit Service-User | ohne: Hit-Counter, Deny-List, Sessions und Diff laufende/gespeicherte Config fehlen | Service-User einrichten (3.1) |
| Zeitfenster über Datei-mtime | rotierte Logs älter als das Fenster fehlen; große `httpaccess*` über `ACCESS_LOG_MAX_MB` begrenzt; die Quell-IP eines Versuchs fehlt, wenn das Access-Log rotiert ist (der Report sagt, wo es im Snapshot-Set liegt) | Zeilenfilter nach Zeitstempel als Kandidat |
| Quell-IP bei einem einzelnen Versuch | Offset-Suche braucht mindestens 2 Versuche | bleibt, bewusst gegen Fehlzuordnung |
| Block 5 findet nur bekannte Muster | ein leerer Block 5 ist kein Freispruch | bleibt; deshalb Runbook Schritt 7 |
| Quell-IP-Zuordnung bei Logon-Zeilen ist zeitliche Nähe | ein unbeteiligter Logon-Request derselben Sekunde kann erscheinen | bleibt; deshalb "passt zu n von m Versuchszeiten" und "schwach", nie als Fakt. Bei Responder-Zeilen nur die Adresse aus der Zeile |
| Bedingungen außerhalb von `ns.conf` und `tcpParam` | nicht per Regel abbildbar, konservativ `all` | bleibt, Changelog "Nicht abgebildet" |
| `--compare` vergleicht Web-Dateien nach mtime und Größe | wer mtime zurücksetzt, fällt erst beim Hash auf | V18: Hash-Vergleich, Cron, httpd.conf-Hash, SUID |
| Anonymisierung | erkennt nur, was in `ns.conf` steht oder privat ist | bleibt; Stichprobe vor Weitergabe |
| Custom-Datei | kann nur strenger bewerten und nur Indikatoren und Fix-Builds beisteuern; Prüfmuster nur über ceterion | gewollt |
| Adressliste | enthält Beobachtungen, keine Bewertung; NAT und CDN liefern Unbeteiligte | gewollt; Hinweis im Dateikopf |
| `--ki-bundle` nimmt die zwei jüngsten Dateien je Log | auf ruhigen Appliances bleiben Abschnitte leer | V18: ältere Rotationen |
| Schwellen in Block 4 (4.3) | an einem Lab-Gateway kalibriert; andere Umgebungen brauchen andere Werte | Config; Fehlalarm-Richtung je Schwelle in 4.3 |
| Webshell-Namen mit variabler Nummer (Zscaler 16.10.: `Nx_<nummer>.php/.pl/.html` in sechs Verzeichnissen, Nummer je Angriffsinstanz anders) | Format 2 kennt für `path` nur exakte Werte; die `.php` fängt die generische Prüfung "PHP außerhalb admin_ui" (Rot), `.pl` und `.html` nur "neue Web-Datei seit Boot" (Gelb) | V18: Regex-Variable `WEBSHELL_NAME_RE` mit Muster `Nx_[0-9]+\.(php\|pl\|html)`; bis dahin exakte Pfade (Regelstand 2026-10-22b) |
| Schläfer jenseits des Fensters (Vorgabe 72 h, im Lab 168 h) | wer länger als das Fenster pausiert, fällt erst über die kumulierte Adressliste auf | gewollt; Liste nie löschen |
| Ausgaben nur deutsch | Report, Terminal und Befundtexte im JSON sind deutsch; Feldnamen, Verdicts und RESULT sind sprachneutral | V18: Nachrichtenkatalog und `--language en` |
| Shell-Logs (`bash.log`, `sh.log`) werden nicht bewertet | Persistenz über die Shell bleibt unentdeckt, bis Regeln vorliegen | V18, Regel-Entwurf zuerst |

Erledigt seit v22: `--compare` entpackt nicht mehr nach `/tmp` (17.3, eigenes Arbeitsverzeichnis mit Platzprüfung); Reports liegen seit Snapshot V9 im Archiv 3; `EOL_RELEASES` wird ausgewertet (17.4); IP-Indikatoren treffen nicht mehr als Teilstring (17.0).

## 13. Testen (ceterion und Power-User)

`docs/release.sh` führt vor jedem Release aus: Kopien-Check, Plattform-Lints (kein `{ }` in `$( )`, kein `\t` in sed-Ersetzungen, keine Intervalle `{n,m}` in awk; `docs/PLATFORM.de.md`), Format-2-Lint, Präfix-Prüfung, Herkunftsprotokoll, 54 Testlogs (`docs/testlogs/`, Erwartungen in `expected.txt`, Herkunft je Zeile in `herkunft.md`), 6 Fixtures (`clean`, `compromised`, `eol`, `custom`, `blocked`, `nologs`; Erwartungen inklusive RESULT-Felder in `fixture-expected.txt`). Testlogs und Fixtures sind konstruiert aus veröffentlichten Beschreibungen, Adressen RFC 5737; nie auf eine Appliance kopieren.

## 14. Zugehörige Repositories und Kontakt

Fragen und Abnahme-Unterstützung: netscaler-integrity@ceterion.com. Sicherheitsfehler im Script: security@ceterion.com (SECURITY.md), nie als öffentliches Issue. Fehlalarme und übersehene Indikatoren: Issue mit dem anon-Report.

| Repository | Zweck |
|---|---|
| `netscaler-snapshot` | täglicher Datei-Snapshot je Appliance (vier Archive, Manifest mit SHA-256, Laufzeitzustand); Archiv 3 enthält seit V9 die Quickcheck-Reports |
| `netscaler-collector` | Auswertung der Snapshot-Sets und Reports über Geräte und Zeit (PowerShell 7); eigene Engine für die Regeldatei nach `rules-format-2.md` |

## 15. FAQ

### Alles ist Gelb, was tun

In dieser Reihenfolge, jeder Schritt lässt Befunde verschwinden, ohne etwas zu verstecken:
1. Gesperrte Adressen und Netze in `ns_quickcheck.blocked_ips` eintragen (5.4): Dropper, Sondierung und Injection-Download-Hosts werden Orange und zählen nicht mehr.
2. Bestätigte Theme-Dateien in die Whitelist (Howto unten): Block 5 wird leer.
3. Admin-Netze in `MGMT_NET_RE` (4.2): Management- und SSH-Meldungen von eigenen Arbeitsplätzen verschwinden, eigene Adressen bei Anmeldefehlern werden als "intern" geführt.
4. `PROBE_LEVEL=info`, wenn Sondierungen nur noch gezählt werden sollen.
5. AAA-Schwellen (4.2) an die Umgebung anpassen, nachdem die Kontenliste im Original-Report gezeigt hat, welche "unklar"-Fälle Menschen waren.
Was danach noch Gelb ist, ist neu oder braucht eine Entscheidung; das Verdict wird `OK`, sobald nur Orange und INFO bleiben.

### Wen rufe ich an

| Befund | Anruf |
|---|---|
| "unklar, ein Konto in kurzem Burst" | den Nutzer des Kontos (steht im Original-Report): Client oder gespeichertes Passwort erneuern |
| "Anmeldefehler von eigenen oder internen Adressen" | den Betreiber des Systems hinter der Adresse (`ns.conf`-Objekt oder Netzplan): Dienstkonto, Monitoring, Test |
| Brute Force auf ein Konto | den Kontoinhaber und den Helpdesk: Konto sperren oder Passwort ändern, MFA prüfen, woher der Name bekannt ist |
| Treffer (Rot) | Incident-Prozess, nicht den Nutzer zuerst: Konto sperren, Sitzungen beenden, dann fragen |
| Maschinen, Netze, Schläfer, Sondierung | Firewall und SOC mit der Adressliste; niemanden anrufen |

### Howto Whitelist: bestätigte Web-Dateien ausnehmen

Datei `ns_quickcheck.whitelist` neben dem Script (Vorlage `ns_quickcheck.whitelist.example`, Rechte 600), eine Regel je Zeile `<typ>:<regex>`, Typen `webfile`, `user`, `listener`, `path`, `cron`. Fehlt die Datei, steht "Whitelist: nicht vorhanden" im Kopf, und jeder Befund bleibt ungefiltert.

**Drei Regelformen für `webfile`, keine andere:**

| Form | So sieht sie aus | Was sie freigibt | Wofür |
|---|---|---|---|
| Verzeichnis | `webfile:^/var/netscaler/logon/themes/MeinTheme/` (endet mit `/`) | alles darunter, auch künftige Dateien und Änderungen; **nie Code** (`.js`, `.php`, `.pl`, `.sh`, `.cgi`, `.py`, `plugins.xml`) | **unterstützt, nicht empfohlen**: eine neue Bilddatei mit Nutzlast bliebe unsichtbar; stattdessen `--pin-all <ordner>` (WORKFLOW, Whitelist) |
| Datei | `webfile:^/var/netscaler/logon/LogonPoint_workspace/custom/style\.css$` (endet mit `$`) | genau diese Datei, auch nach Änderungen | einzelne Bilder, CSS, JSON, Favicons |
| Datei mit Pin | `webfile:^/var/netscaler/logon/LogonPoint_workspace/custom/script\.js$@sha256=<64 hex>` | genau diesen Stand der Datei; die nächste Änderung ist wieder ein Befund | **Pflicht für Code** |

Eine Regel, die weder mit `/` noch mit `$` endet, trifft mehr als gewollt (`themes/obj108` trifft auch `obj1080`); der Kopf warnt. Eine Dateiregel auf Code ohne Pin ist wirkungslos; der Kopf warnt.

**Pflege in fünf Schritten:**

1. Befund in Block 5 lesen: Welche Dateien, wann geändert (jede Zeile trägt die Änderungszeit, neueste zuerst), gibt es dazu ein Ticket oder einen Vorgang? Ohne Vorgang keine Regel; dann Schritt 3 der "Zu tun"-Zeile.
2. Für Bilder, CSS, JSON, Favicons und ganze Theme-Ordner: Verzeichnis- oder Dateiregel eintragen, darüber eine Kommentarzeile mit Datum und Ticket.
3. Für Code: erst den Inhalt gegen die Vorversion vergleichen (Snapshot-Set oder Backup), dann die Pin-Zeilen erzeugen lassen und übernehmen:
   ```
   sh /var/nssnapshot/ns_quickcheck.sh --pin /var/netscaler/logon/LogonPoint_workspace/custom/ >> /var/nssnapshot/ns_quickcheck.whitelist
   ```
   Die Zeilen enthalten den aktuellen Hash; was nicht gewollt ist, vor dem Übernehmen löschen.
4. Lauf wiederholen: Der Befund ist weg, oder der Kopf nennt eine Regel, die keiner Form entspricht.
5. Nach einem Theme- oder Portal-Update: Verzeichnisregeln bleiben gültig; für geänderten Code meldet der Lauf "per Hash freigegebene Web-Datei erneut geändert", dann Schritt 3 für genau diese Dateien.

Beispiel einer gepflegten Datei:

```
# 2026-10-15 CHG-1234 Theme MeinTheme (Bilder, CSS, Strings)
webfile:^/var/netscaler/logon/themes/MeinTheme/
webfile:^/var/netscaler/gui/admin_ui/common/images/favicon\.ico$
# 2026-10-23 CHG-1301 Workspace-Portal; Code gepinnt nach Diff gegen Snapshot vom 22.10.
webfile:^/var/netscaler/logon/LogonPoint_workspace/custom/
webfile:^/var/netscaler/logon/LogonPoint_workspace/custom/script\.js$@sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
webfile:^/var/netscaler/logon/LogonPoint_workspace/custom/strings\.de\.js$@sha256=89abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567
```

Regeln: Pfade so eng wie möglich (ein Theme-Ordner, nicht `/var/netscaler/logon/`), Punkte maskieren (`\.`), nie `.*` am Anfang. Die Whitelist wirkt nur auf "Web-Dateien seit Boot"; die Prüfung "PHP außerhalb admin_ui" und die Pfad-Indikatoren der Regeldatei lassen sich nicht ausnehmen.

### Howto Responder-Quelle: Client-Adresse in der Responder-Zeile

Eine Responder-Policy, die den Injection-Versuch abweist, hält den Request in der Packet Engine auf; er erreicht den Webserver nicht und steht in keinem Access-Log. Die Quelle kennt dann nur die Policy selbst. Standardmäßig protokolliert der Responder nur den Policy-Namen; mit einer Audit-Message-Action schreibt er Client-Adresse, Host-Header und Request in die Syslog-Zeile, und das Script liest die Quelle direkt daraus ("Quelle: ... (aus der Responder-Zeile)").

```
add audit messageaction am_rs_badrequest WARNING "\"Bad Request (\" + HTTP.REQ.HOSTNAME + \" - \" + \"<policyname>\" + \") from IP \" + CLIENT.IP.SRC + \" - Hostname: \" + HTTP.REQ.HOSTNAME + \" - URL: \" + HTTP.REQ.URL.PATH_AND_QUERY + \" (headers: \" + HTTP.REQ.FULL_HEADER + \")\"" -logtoNewnslog YES
set responder policy <policyname> -logAction am_rs_badrequest
save ns config
```

Den Ausdruck an die eigene Policy anpassen; entscheidend ist `from IP ` gefolgt von `CLIENT.IP.SRC`. Hinweis: `HTTP.REQ.FULL_HEADER` schreibt den kompletten Request-Header ins Syslog, auch Cookies und Authorization-Header; wer das nicht will, nimmt `HTTP.REQ.HEADER("User-Agent")`. Die Zeile wird lang; `LINE_MAX` in der Config gilt für Injection-Zeilen nicht, sie stehen immer vollständig im Report. Der Host-Header (die Adresse, unter der der Angreifer das Gateway ansprach) wird in der anon-Fassung maskiert, sofern er kein bekannter Angreiferwert ist.

### Howto Lockout: Konten nach Fehlversuchen sperren

Die Appliance kann Konten nach einer Zahl von Fehlversuchen für eine Zeit sperren (Citrix-Doku "User account and password management", Abschnitt "Configure lockout"):

```
set aaa parameter -maxloginAttempts 5 -failedLoginTimeout 15 -persistentLoginAttempts ENABLED
show aaa parameter
unlock aaa user <konto>
```

`maxloginAttempts` zählt Fehlversuche je Konto, `failedLoginTimeout` ist die Sperrdauer in Minuten, `persistentLoginAttempts ENABLED` hält den Zähler über Sitzungen und Neustarts. Was das bringt und was nicht: Gegen Brute Force auf ein Konto wirkt es sofort, nach fünf Versuchen ist Schluss. Gegen Password Spraying wirkt es nicht, denn ein Versuch je Konto bleibt unter jeder Schwelle; dagegen hilft nur die Netzsperre an der Firewall und MFA. Und es hat eine Kehrseite: Wer den Kontonamen kennt, kann das Konto mit fünf falschen Passwörtern sperren; für Administratorkonten am Gateway deshalb nur mit MFA und einem zweiten Weg hinein (Konsole, Management-Netz). Ab Build 13.1 gilt der Parameter für Systemkonten und externe Konten; Details und Versionsstände in der Citrix-Doku prüfen.

### Howto Feldbefund: eigene Adresse in die Custom-Datei

Datei `ns_quickcheck.rules.custom` neben der Regeldatei (Vorlage `ns_quickcheck.rules.custom.example`). Eine Zeile vor der schließenden Marke `IOC` einfügen, Felder mit Tab:

```
ip	203.0.113.11	betreiber	2026-10-19	c	eigener Access-Log, Dropper-Suche 17. bis 19.10.	betreiber-2026-10-21
```

Felder: Typ (`ip`, `dom`, `hash`, `path`), Wert, Quelle (`betreiber`), Datum der Beobachtung, Klasse `c`, Fundstelle (woher du es weißt, ohne Namen), Stand. Danach `CUSTOM_VERSION` in der Datei auf das Datum setzen und ein Lauf; die Kopfzeile zeigt die neue Zeilenzahl. Ab jetzt meldet jede Appliance mit dieser Custom-Datei Rot, sobald die Adresse in Logs, Verbindungen oder Requests auftaucht, mit "Quelle: betreiber". Wer nicht in der Datei editieren will: Patch mit `IOC:`-Zeile und `sh docs/rules-apply.sh ns_quickcheck.rules.custom <patch>` (WORKFLOW Schritt 3); das prüft Format und Dubletten.

Ein Feldbefund gehört nie in ein Issue (die Adresse ist dein Befund, die Fundstelle dein Log); nennt ein Veröffentlicher sie später, kommt sie über die Regeldatei zu allen.


**Rot, obwohl der Build gefixt ist?** Rot in Block 4 auf gefixtem Build heißt: Jemand hat es versucht, der Versuch konnte nicht wirken. Die Detailzeilen sagen, was zu prüfen ist (Firewall-Log für den Download-Host, Access-Log für die Quelle). Verdict ist dann `INVESTIGATE`, nicht `FORENSICS_FIRST`.

**Jeden Tag dasselbe Gelb?** Meist "Web-Dateien seit Boot geändert" nach einer Theme-Anpassung. Datum gegen das Ticket prüfen, dann die Pfade in `ns_quickcheck.whitelist` als `webfile:<regex>` eintragen; die Meldung verschwindet.

**Was darf ich weitergeben?** Nur `_anon.txt`, `_anon.json` und nach Prüfung `_ips.tsv`. Niemals das Original, nie die Zuordnungstabelle, nie die Custom-Datei, nie ein Bundle ohne Anonymisierung.

**Custom-Datei wird nicht geladen?** `ls -l`: Name genau `ns_quickcheck.rules.custom`, im Ordner der Regeldatei, Rechte 600. Die Kopfzeile "Custom-Datei des Betreibers geladen" bestätigt es; `custom=none` in RESULT heißt nicht gesehen.

**`--compare` meldet "filesystem is full"?** Script älter als 17.3; es entpackte nach `/tmp` auf dem kleinen Root-Dateisystem. Update, dann `rm -rf /tmp/qc.*`.

**Warum fehlt die Quell-IP eines Versuchs?** Sie steht nur im Access-Log, und das war für den Zeitpunkt rotiert. Das Snapshot-Set des Folgetags enthält es; der Report nennt den Zeitpunkt, nach dem zu suchen ist.

**Zuordnungstabelle gelöscht, was passiert?** Der nächste Lauf vergibt neue Ersatznamen. Alte und neue anon-Reports passen dann nicht mehr zueinander; sonst nichts.

**Kann ich das Script im Change-Prozess freigeben?** Es ändert nichts an der Appliance und schreibt nur in seine eigenen Verzeichnisse (Abschnitt 10): keine Änderung an der Appliance, keine Netzwerkverbindung, keine Datenübertragung; es schreibt Reports nach `/var/nssnapshot/quickcheck/` und eine Zuordnungstabelle neben die Regeldatei. Laufzeit 5 bis 30 Sekunden.

## 16. Glossar

| Begriff | Bedeutung |
|---|---|
| NSIP, SNIP, VIP | Management-Adresse der Appliance; Subnetz-Adresse für Backend-Verkehr; Adresse eines vServers |
| Packet Engine (PPE) | der Prozess der Appliance, der den Netzwerkverkehr verarbeitet; `0-PPE-0` bis `0-PPE-3` in Logzeilen sind die einzelnen Engines, eine Welle über alle Engines ist ein Angriff, der parallel ankam |
| `127.0.0.2` im Webserver-Log | die Appliance selbst. Gateway-Verbindungen nimmt die Packet Engine an; was an den Webserver muss (Logon-Seite, Themes, EPA), reicht sie intern über Loopback weiter. Der Webserver sieht deshalb als Client immer `127.0.0.2`, nie den Nutzer oder Angreifer. Die echte Adresse steht im Access-Log zur selben Zeit. Eine andere Client-Adresse im Webserver-Log heißt: direkter Zugriff am Gateway vorbei, meist über die NSIP |
| SAML SP, IdP | NetScaler als Service Provider (nimmt Anmeldungen von einem IdP an) oder als Identity Provider; CVE-2026-88779 und 107406 betreffen nur SAML-Konfigurationen |
| DTLS | UDP-Variante von TLS, von Gateway für EDT genutzt; Voraussetzung für CVE-2026-88772 |
| Enhanced ISN Generation | TCP-Parameter, den CTX697096 für CVE-2026-88778 verlangt; muss nach dem Upgrade gesetzt werden |
| Responder-Policy, Mitigation | Regel, die Requests vor der Anmeldung abweist; Citrix-Workaround bis zum Patch |
| Injection, Log-Poisoning | Angriff über das Login-Feld, das Befehle in Logzeilen schreibt, die später ausgeführt werden (CVE-2026-88771) |
| Payload, Download-Host | das nachgeladene Script oder Programm des Angreifers; die Adresse, von der es geholt wird |
| Dropper | Paket, das als Linux-Client getarnt die eigentliche Schadsoftware bringt (`nsg64.deb` und ähnliche) |
| Webshell | Datei im Web-Verzeichnis, über die ein Angreifer Befehle ausführt |
| nsaaad | Authentifizierungsdienst der Appliance; sein Absturz ist bei SAML auf offenem Build ein Angriffszeichen |
| Snapshot-Set | die vier Archive eines Snapshot-Laufs (Config, Dateisystem, Logs, Laufzeit) mit Manifest |
| Fixture, Testlog | konstruierte Prüfdaten im Repo, mit denen Script und Regeln vor jedem Release getestet werden |
| Fundstelle, Erstautor | die Veröffentlichung, in der ein Indikator zuerst stand; nur sie zählt als Quelle |
| Password Spraying | wenige Passwörter gegen viele Konten, meist ein Versuch je Konto, unter jeder Lockout-Schwelle; Gegenmittel Netzsperre und MFA |
| Brute Force | viele Passwörter gegen ein Konto; Gegenmittel Lockout und Konto sperren |
| Schläfer | Spraying so langsam, dass Takt- und Kontenschwellen nicht greifen; erkennbar nur über Tage |
| Maschine, Nutzer, unklar | Bewertung einer Adresse mit Anmeldefehlern nach Takt, Konten, Netz und Erfolg danach (4.3) |
| Treffer | erfolgreiche Anmeldung nach einer Fehlserie; Kompromittierungszeichen, bis ein Mensch das Gegenteil feststellt |
| Orange, abgedeckt | Befund zu einer Adresse, die laut Sperrliste vor der Beobachtung gesperrt war; zählt nicht als Spur |
| `coverage` | `full` oder `partial` in RESULT: ob jede Kernprüfung Daten hatte; `partial` verhindert `OK` |
| Defanged | URLs mit `hxxp` geschrieben, damit sie nicht anklickbar sind; Adressen stehen seit 17.18 unmaskiert |

## 17. Changelog README

| Version | Datum | Änderung |
|---|---|---|
| v36 | 2026-10-28 | Script 17.42: Cores (`.gz`, Verzeichnisse, `CORE_BOOT_LEVEL`), Regelstand e |
| v35 | 2026-10-28 | Script 17.41: Abstürze "lieber mehr", Bewertung, `crashes=`, kumulierte Absturzdatei |
| v34 | 2026-10-28 | Script 17.38: Verdict-Text, `vuln_open`, Anonymisierung von URLs und Domänen |
| v33 | 2026-10-28 | Script 17.37: Fix-Build `pending` in der CVE-Tabelle; Runbook Schritt 7 nur noch Citrix-IoC-Scan |
| v32 | 2026-10-27 | Script 17.36: Verzeichnisregeln nicht empfohlen (15, WORKFLOW ACHTUNG-Block), Zeitstempel je Web-Datei auf der Appliance |
| v31 | 2026-10-27 | Script 17.34: Howto Whitelist neu (drei Regelformen, fünf Schritte, `--pin`), Web-Dateien mit Änderungszeit und Gruppierung, Zuordnungstabelle übergeht ungültige Einträge |
| v30 | 2026-10-27 | Script 17.33: Whitelist-Hash-Pin und `$`-Warnung (15), Web-Dateien-Einordnung über alle Dateien, Anonymisierer-Schutz für Reportwörter |
| v29 | 2026-10-27 | Script 17.32 und Regelstand 2026-10-27: Selbsttreffer durch nsprofmon beseitigt, Prozessabstürze als Ereignisse (Block 4), anonymisierte Adresslisten und Share-Datei (5.2) |
| v28 | 2026-10-27 | Script 17.31: Vertrauensliste (5.5), `TRUST_LEVEL`, `FOOTER`, `--trusted`; Fußzeile im Report |
| v27 | 2026-10-23 | Script 17.30 und Regelstand 2026-10-23: CTX697263 (PHP2Shell, Fix 14.1-73.49 / 13.1-64.32 seit Regelstand 2026-10-28) in Block 1, 2, 4b und 5; `PHP_ANOMALY_MIN`; `vuln63` |
| v26 | 2026-10-22 | Schnellstart nach `/var/nssnapshot/`; 8.7 ohne Nennung einzelner Community-Werkzeuge; englische Fassung `ns_quickcheck_README.en.md` |
| v25 | 2026-10-22 | Korrekturen nach Review: Sperrliste 5.4 auf drei Felder, `--hours`-Vorgabe 72 (plus `HOURS` in 4.2), `webshell_hit` in 5.2, elf Spalten der kumulierten Liste, Verdict-Regeln nach 7.1, Service-User-Quellen in 4.2 und 10 |
| v24 | 2026-10-21 | Für Script 17.29 und Regelstand 2026-10-21d: gelesene Logs (3), Konfiguration (4.2) und Schwellen (4.3) als Tabellen, Block 4 in vier Gruppen mit den AAA-Befunden (Treffer, Brute Force, Schläfer, Spraying, intern), `coverage`, Sperrliste, Adressliste mit 11 Spalten, Howtos Responder-Quelle und Lockout, FAQ "Alles ist Gelb" und "Wen rufe ich an", Glossar |
| v23 | 2026-10-21 | Neu geschrieben für Script 17.9: Titel, Abschnitte ab 1, vollständige Optionstabelle, Sicherheitsbetrachtung, Schnellstart, Verdict-Entscheidungstabelle, Adressliste, Anonymisierung, Herkunftsprotokoll, Custom-Datei, JSON, FAQ, Glossar, Grenzen bereinigt, Abschnittsnummern bereinigt |
| v22 | 2026-10-20 | Verdict-Begriffe `UPDATE`, `INVESTIGATE` |
| v21 | 2026-10-15 | Script-V15, Release-Struktur |
| v5 bis v20 | 2026-10-08 bis 10-14 | Entwicklungsstände, siehe CHANGELOG.md |
