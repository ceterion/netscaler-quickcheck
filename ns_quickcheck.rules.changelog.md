# ns_quickcheck.rules - Änderungshistorie

Ein Eintrag je Änderung ab dem ersten veröffentlichten Regelstand (2026-10-19), neueste oben; die Entwicklungsphase davor steht am Ende als Vorgeschichte. Oberer Teil: Anlass und Belege (von Bearbeiter oder KI-Vorschlag). Unterer Teil: Test, Verteilung, Bearbeiter (immer vom Bearbeiter). Format und Pflegeprozess: `ns_quickcheck_README.md`, Abschnitt 7.

---

## 2026-10-28e - RULES_VERSION 2026-10-28e

**Anlass:** Stock-Hash fuer 14.1-73.49.

| Variable | Änderung | Quelle |
|---|---|---|
| `STOCK_FILE_b8ea6f58168ed41f00829c527790aa22ae5358ccded5ffdfd8dc06542a8c5e4dES` | `netscaler/ns_monuploadd_err.pl` fuer 14.1-73.49: `02b24a99...` (derselbe Wert wie 73.46) | zwei unabhaengige Appliances, Lab nach Upgrade und ein Betreiber-Gateway, 28.10. |

Keine Indikatoren geändert.

**Vorher:** 2026-10-28d | **Nachher:** SHA-256 b8ea6f58168ed41f00829c527790aa22ae5358ccded5ffdfd8dc06542a8c5e4d
**Test (Bearbeiter):** Fixtures grün, Lab-Lauf 73.49 zeigt OK statt INFO
**Bearbeiter:** ceterion AG, Jens Miltenberger

---

## 2026-10-28d - RULES_VERSION 2026-10-28d

**Anlass:** Linie "lieber mehr reporten": jeder Hinweis auf einen Prozess, der nicht freiwillig gegangen ist. Formate aus Apache- und FreeBSD-Doku, nicht aus dem Lab; als Standard markiert, Testlog `crash-extra.log`.

| Variable | Inhalt | Quelle |
|---|---|---|
| `HTTPERR_CRASH_RE` | Apache-Worker-Absturz `AH00052: child pid <pid> exit signal <name> (<n>)` im Webserver-Fehlerlog; fuer PHP2Shell die wahrscheinlichste Spur | Apache-Doku (Standard) |
| `KERNEL_MEM_RE` | `swap_pager: out of swap space`, `was killed: out of swap space` | FreeBSD (Standard) |
| `KERNEL_PANIC_RE` | `kernel: panic:`, `Fatal trap <n>`, `kernel trap <n> with interrupts disabled` | FreeBSD (Standard) |

Keine Indikatoren geändert.

**Vorher:** 2026-10-28c | **Nachher:** SHA-256 9f445666a48ad5c990ffef872649002a524e7f486d0b5a196fb784b669561524
**Test (Bearbeiter):** --testlog mit `crash-extra.log`, Fixtures grün
**Bearbeiter:** ceterion AG, Jens Miltenberger

---

## 2026-10-28c - RULES_VERSION 2026-10-28c

**Anlass:** Lab 28.10., Zeilen des Pitboss-Prozesses selbst, die nur das alte Muster kannte.

| Variable | Änderung | Quelle |
|---|---|---|
| `PITBOSS_RE` | plus `pitboss[<n>]: proc <proc> (<pid>) SIGNALED` und `EXITED with status 0x<hex>` (0x8b = 128 + Signal 11); dritte Zeilenart desselben Absturzes, liefert das Signal auch ohne Kernel-Zeile | Lab-Zeilen 28.10. (verifiziert) |

Keine Indikatoren geändert. Damit sind alle im Lab beobachteten Pitboss- und Kernel-Zeilen eines nsaaad-Absturzes verankert; die INFO "unbekanntes Format" sollte auf 14.1 nicht mehr erscheinen.

**Vorher:** 2026-10-28b | **Nachher:** SHA-256 6a8fc3882fa3d82ec6bc6737b4922e8699dd10b86e110f9ab704ad9450c5a6b7
**Test (Bearbeiter):** --testlog 63 PASS, Fixture `crash` 4 Ereignisse
**Bearbeiter:** ceterion AG, Jens Miltenberger

---

## 2026-10-28b - RULES_VERSION 2026-10-28b

**Anlass:** zwei weitere `kill -SEGV` im Lab (ns-lab-141, 28.10.): drei Zeilenarten, die das Script bisher als "unbekanntes Format" meldete.

| Variable | Änderung | Quelle |
|---|---|---|
| `PITBOSS_RE` | plus `collecting core dump on <proc> (<pid>)` (Beleg zum selben Absturz) und `Adding pitboss watch on (<pid>) for (` (Neustart abgeschlossen, kein Ereignis) | Lab-Zeilen 28.10. (verifiziert) |
| `KERNEL_EXIT_RE` | plus `kernel: Core dump of pid <pid> (<proc>)`; die Zeile nennt das Core-Muster `/var/core/%N-%P`, Cores liegen als Dateien `<proc>-<pid>` | Lab-Zeile 28.10. (verifiziert) |

Keine Indikatoren geändert.

**Vorher:** 2026-10-28 | **Nachher:** SHA-256 48838e67d7afa4a99cf0ad4b623cba7c75adfbd447960636de8a5877436b33a4
**Test (Bearbeiter):** --testlog 63 PASS (pitboss-crash.log um die drei Zeilenarten erweitert), Fixture `crash` mit Core-Datei im Manifest
**Bearbeiter:** ceterion AG, Jens Miltenberger

---

## 2026-10-28 - RULES_VERSION 2026-10-28

**Anlass:** CTX697263 am 27.10. aktualisiert ("Updated remediation versions"): Die Fix-Builds für PHP2Shell sind **14.1-73.49, 13.1-64.32, 14.1-FIPS 73.49, 13.1-FIPS/NDcPP 37.286**. Der Regelstand 2026-10-23 hatte 73.41 / 64.28 / 37.282 eingetragen; das waren die Fix-Builds des SAML-Bulletins CTX697191, die der Citrix-Blog in derselben Übersicht nannte, nicht die von CTX697263. Am 23.10. gab es noch keinen Fix-Build für PHP2Shell; jede Appliance unter 73.49 bzw. 64.32 war und ist verwundbar, auch 73.46.

| Typ | Änderung | Quelle |
|---|---|---|
| `CVE_TABLE` (8) | CVE-2026-109618 und 109619: Fix 14.1-73.49, 13.1-64.32, 14.1-FIPS 73.49, 13.1-FIPS 37.286 (NDcPP wie FIPS) | CTX697263, Stand 27.10.2026, Abschnitt "What Customers Should Do" |

Folge für Betreiber: Appliances auf 14.1-73.41 bis 73.46 und 13.1-64.28 bis 64.31 melden ab diesem Regelstand `UPDATE` mit `vuln63=1`; Block 2 zeigt die Management-Adressen ohne DENY-ACL als Gelb. Bis zum Update: Port 80/443 der NSIP und der Management-SNIPs per ACL auf Admin-Netze begrenzen (Citrix-Empfehlung). Der Fehler ist ceterion-intern dokumentiert; die Regeldatei 2026-10-23 und 2026-10-27 sollte nicht mehr verwendet werden.

**Vorher:** 2026-10-27 | **Nachher:** SHA-256 0a74bd585228dab07efa6069c42ee9b847a1d559f576c0519fa7d17b9bbaaabd
**Test (Bearbeiter):** Fixtures und Testlogs grün; `php2shell` (73.37) weiter `FORENSICS_FIRST`
**Bearbeiter:** ceterion AG, Jens Miltenberger

---

## 2026-10-27 - RULES_VERSION 2026-10-27

**Anlass:** Selbsttreffer durch `nsprofmon_mgmt.pl` (CPU-Momentaufnahmen mit den Kommandozeilen von grep und perl des Quickcheck) und Verankerung der Crash-Muster an verifizierten Formaten (Lab ns-lab-141, 14.1, `kill -SEGV` auf nsaaad, 27.10.).

| Variable | Änderung | Quelle |
|---|---|---|
| `PITBOSS_RE` | neu: `PITBOSS[0-9]* Message` mit `unexpectedly died`, `Restarting process ... old pid (n)`, `New pid (n) for (proc) restarts (n)`, Eskalation | Lab-Zeilen 27.10. (verifiziert); Eskalationstexte Annahme aus Citrix-Doku, im Kommentar so markiert |
| `KERNEL_EXIT_RE` | neu: `kernel: pid n (proc), jid n, uid n: exited on signal n` | Lab-Zeile 27.10. (verifiziert) |
| `NSAAAD_CRASH_LEGACY_RE` | neu, identisch mit dem bisherigen `NSAAAD_CRASH_RE`; Treffer nur dort ergeben INFO "unbekanntes Format" | bisheriges Muster |
| `NSAAAD_CRASH_RE` | unverändert, nur noch Rückfall für Scripts vor 17.32 | |

Keine Indikatoren geändert.

**Vorher:** 2026-10-23 | **Nachher:** SHA-256 b3097a1f993daeb22dd9a5295a28b749b71afa5767141aecb716e8689da3c394
**Test (Bearbeiter):** --testlog 63 PASS (neu: pitboss-crash.log mit Selbsttreffer-Zeilen), 9 Fixtures grün (neu: crash), Provenance neu
**Bearbeiter:** ceterion AG, Jens Miltenberger

---

## 2026-10-23 - RULES_VERSION 2026-10-23

**Anlass:** CTX697263 (22.10.2026): PHP2Shell, CVE-2026-109618 und CVE-2026-109619 im Management-Portal (PHP). Erstquellen: Citrix-Blog "Protecting NetScaler Management Access from PHP CVE-2026-109618 & CVE-2026-109619" (die CTX-Seite ist nur per Browser lesbar), Unit 42 und Zscaler 21.10. zum Mechanismus, Red Hat CVE-Eintrag.

| Typ | Wert | Quelle | Fundstelle |
|---|---|---|---|
| `CVE_TABLE` (8) | CVE-2026-109618 und 109619 für 14.1 (73.41), 13.1 (64.28), 14.1-FIPS (73.41), 13.1-FIPS (37.282); Bedingung `all`, weil das Portal auf der NSIP immer läuft | CTX697263 | Abschnitt "Affected Versions" des Citrix-Blogs |
| `HTTPERR_PHP_ANOMALY_RE` | neu | Hypothese | PHP-Standardmeldungen für Out-of-Memory und Fatal Error (`Allowed memory size`, `Out of memory`, `zend_mm_heap corrupted`, `Maximum execution time`); keine veröffentlichte Signatur, Mechanismus laut Unit 42 (longjmp/OOM) |
| `MGMT_ACL_RE` | neu | CTX697263 | Mitigation: DENY-ACLs auf Port 80/443 der Management-Adressen, Platzhalter `NSIP_PLACEHOLDER` wird vom Script je Adresse ersetzt |

Vorbehalte: Citrix nennt "vor 13.1-64.28", warnt aber, dass die Console 13.1-64.23 fälschlich meldet; bis der CTX-Volltext das klärt, gilt 64.28. 13.1-NDcPP (Fix 37.282) ist als Train nicht vorgesehen, Build 37.x wird als 13.1-FIPS bewertet. Die PHP-Muster sind eine Heuristik mit Schwelle (`PHP_ANOMALY_MIN`), auf gefixtem Build nur INFO.

**Vorher:** 2026-10-22b | **Nachher:** SHA-256 bf0668a97539b4532994b4f8d960797320a5d32f73ac1ff5780daab5c2273c73
**Test (Bearbeiter):** rules-apply 2.4 ok, --testlog 57 PASS (neu: httperror-php.log), 7 Fixtures grün (neu: php2shell), Provenance neu
**Bearbeiter:** ceterion AG, Jens Miltenberger

---

## 2026-10-22b - RULES_VERSION 2026-10-22b

**Anlass:** Zscaler ThreatLabz 16.10.2026 (Direktabruf 22.10.), Rest des Artikels nach dem Stand 2026-10-22.

| Typ | Wert | Quelle | Fundstelle |
|---|---|---|---|
| `path` (18) | `Nx_7508.php`, `.pl`, `.html` in `var/vpn/bookmark`, `netscaler/ns_gui/vpn`, `var/netscaler/gui/vpn`, `var/netscaler/logon/LogonPoint`, `var/vpn/theme`, `var/netscaler/gui/admin_ui/apex` | Zscaler ThreatLabz 2026-10-16 | Step 1, dekodierter Base64-Payload (PHP-Webshell, Perl-CGI, Fingerprint-HTML) |
| `ip` (27) | Quelladressen der Exploit-Welle, Tabelle "Potential network indicators" | Zscaler ThreatLabz 2026-10-16 | 28 im Artikel; `82.167.14.7` war bereits über CISA 261399 r1 belegt und bleibt mit dieser Herkunft |

Einschränkung: Die Nummer in `Nx_<nummer>` ist je Angriffsinstanz anders (im Artikel 5936 roh, 7508 dekodiert); exakte Pfade fangen nur die Wiederverwendung desselben Droppers. Muster über die Web-Verzeichnisse (`WEBSHELL_NAME_RE`) kommt mit Script V18. Die `.php`-Varianten fängt bis dahin die generische Prüfung "PHP außerhalb admin_ui" (Rot).

**Vorher:** 2026-10-22 | **Nachher:** SHA-256 0ab860a7ca2269d26148ea29960669eddff20b63e552f1efdd8fddf925dcde48
**Test (Bearbeiter):** rules-apply 2.4 ok, --testlog 54 PASS, Fixtures grün, Provenance neu
**Nachtrag 2026-10-22 (nur Kommentar, gleicher Regelstand):** drei Herkunftskommentare ohne Nennung eines Community-Werkzeugs; Hash oben ist der nach dem Nachtrag
**Bearbeiter:** ceterion AG, Jens Miltenberger

---

## 2026-10-22 - RULES_VERSION 2026-10-22

**Anlass:** Zscaler ThreatLabz, "CVE-2026-88771: Inside the Exploitation of a Critical NetScaler RCE Vulnerability" (16.10.2026), und Nachtrag aus CTX697096 (FIPS-Trains).

| Typ | Wert | Quelle | Fundstelle |
|---|---|---|---|
| `path` | `var/kw2s11` | Zscaler ThreatLabz 2026-10-16 | Inline-Variante 2: `fetch -o /var/kw2s11`, Rust-Binary FreeBSD x64 |
| `ip` | `209.141.43.95` | Zscaler ThreatLabz 2026-10-16 | Download-Server, Infrastrukturüberschneidung mit StyleSmuggler (CVE-2026-75650) |
| `CVE_TABLE` | CVE-2026-88772 und CVE-2026-88778 für 13.1-FIPS (37.279) und 14.1-FIPS (73.37) | CTX697096 | Fix-Builds laut Bulletin für alle CVEs des Bulletins; Bedingungen wie bei 14.1 und 13.1 |

Nicht aufgenommen: ein aus dem Base64-Payload abgeleiteter SHA-256 (nicht vom Veröffentlicher genannt; eigener Befund, verbleibt in der Betreiber-Custom). Noch offen aus demselben Artikel: 28 Quell-Adressen der Exploit-Welle, Webshell-Namen `Nx_7508.*` in sechs Pfaden, `INDEX:`-Marker im User-Agent (Script-Thema).

**Vorher:** 2026-10-21d | **Nachher:** SHA-256 db76fb01c775d0d4fd27aae4b163d5b3ddb6157c669268942e1f28c296a48882
**Test (Bearbeiter):** rules-apply 2.4 (Format-2-Lint, Syntax, Präfix) ok, --testlog 54 PASS, Fixtures grün, Provenance neu erzeugt
**Bearbeiter:** ceterion AG, Jens Miltenberger

---

## 2026-10-21d - RULES_VERSION 2026-10-21d

**Anlass:** Paarung Fehlserie und Erfolg je Adresse und Konto (Script V17.25). Keine neuen Indikatoren.

| Variable | Art | Inhalt | Beleg |
|---|---|---|---|
| `AAA_OK_RE` | neu | erfolgreiche Gateway-Anmeldung: `AAA LOGIN ... Context`, `SSLVPN LOGIN`, `authenticate user: succeeded` | NetScaler-Audit-Logging (Citrix-Dokumentation) |

**Vorher:** 2026-10-21c | **Nachher:** SHA-256 bc618f91202304b96cd126a1deb2a0a7b7d5addc8126128eee4cc63e88941fc7
**Test (Bearbeiter):** Format-2-Lint ok, --testlog 54 PASS, Fixtures grün
**Nachtrag 2026-10-21 (nur Kommentar, gleicher Regelstand):** Entfernungsnotiz vom 19.10. ohne Parteinamen formuliert; Hash oben ist der nach dem Nachtrag
**Bearbeiter:** ceterion AG, Jens Miltenberger

---

## 2026-10-21c - RULES_VERSION 2026-10-21c

**Anlass:** Gateway-Anmeldefehler (Script V17.22). Keine neuen Indikatoren.

| Variable | Art | Inhalt | Beleg |
|---|---|---|---|
| `AAA_FAIL_RE` | neu | `AAA LOGIN_FAILED`, `authenticate user: failed`, `SSLVPN LOGIN_FAILED` | NetScaler-Audit-Logging (Citrix-Dokumentation) |

**Vorher:** 2026-10-21b | **Nachher:** SHA-256 368bfd76c4428d47ef51f6923ba9b15435d6832398236980f740ba0358d41394
**Test (Bearbeiter):** Format-2-Lint ok, --testlog 51 PASS (neu: aaa-fail.log), Fixtures grün
**Bearbeiter:** ceterion AG, Jens Miltenberger

---

## 2026-10-21b - RULES_VERSION 2026-10-21b

**Anlass:** Weitere Logs des Scripts (V17.19): Webserver-Fehlerlog, Management-Zugriffe, Anmeldungen. Keine neuen Indikatoren.

| Variable | Art | Inhalt | Beleg |
|---|---|---|---|
| `HTTPERR_EXEC_RE` | neu | Interpreter-Fehler: PHP Parse/Fatal/Warning, Premature end, script not found | Apache-Standardmeldungen |
| `HTTPERR_PROBE_RE` | neu | "File does not exist" fuer Webshell-Namen (.ctxs*, .local_journal, .slap*, .nsmon, .ux), PHP-Varianten, Scanner-Pfade; Lab-Lauf 21.10.: Sondierung von .ctxs.receiver in allen Theme-Ordnern | Webshell-Namen aus CTX697096, Unit 42 30.09., LevelBlue 02.10., CISA 261399 r1 |
| `AUTH_LOGIN_RE`, `AUTH_FAIL_RE` | neu | sshd Accepted/Failed/Invalid user, Konsolen-Login | OpenSSH- und FreeBSD-Standardmeldungen |
| `MGMT_PATH_RE` | neu | Requests auf /nitro/v1/, /menu/, /admin_ui/, /rapi/ | NetScaler-Dokumentation NITRO und GUI |

**Vorher:** 2026-10-20 | **Nachher:** SHA-256 525e16a9a266834cec12a245c68b79f695eb1615a8a98e87be41af7d01db4a9e
**Test (Bearbeiter):** Format-2-Lint ok, --testlog 49 PASS (neu: httperror.log, auth.log, httpaccess-mgmt.log), Fixtures grün
**Bearbeiter:** ceterion AG, Jens Miltenberger

---

## 2026-10-20 - RULES_VERSION 2026-10-20

**Anlass:** Übergabe aus dem Collector-Chat (20.10.): Dublette `path netscaler/ns_gui/vpn/c88771.json` (zweimal, Sygnia) erzeugte einen doppelten Rotbefund. Zeile entfernt; `rules-apply.sh` und `release.sh` prüfen Dubletten (typ plus wert) seit 2.2 beziehungsweise mit dem Format-2-Lint. 111 IOC-Zeilen. Zusätzlich Kommentare und RULES_SOURCE bereinigt: nur noch Erstautoren als Datenquellen; generische Techniken auf GTIG und CISA verwiesen.
**Nachher:** SHA-256 4138048f1c3d098d7c2b186ea2c66de702062e7945b4acd087d24a9f9c5a085b
**Test (Bearbeiter):** Format-2-Lint ok, --testlog 31 PASS (neu: ip-boundary.log, ip-substring.log für Script-V17), Fixtures grün mit RESULT-Feldern
**Bearbeiter:** ceterion AG, Jens Miltenberger

---

## 2026-10-19 (Format 2) - RULES_VERSION 2026-10-19

**Anlass:** Umstellung auf Format 2 (Script V16): jede Indikator-Zeile trägt Quelle, Datum, Klasse und Fundstelle. Inhalt wie 2026-10-19 Format 1 nach der Bereinigung; dazu Zuordnung je Wert aus Changelog und Script-Kommentaren. 203 Zeilen (118 ip, 19 dom, 24 hash, 42 path); 89 Zeilen PRUEFEN (Primärfundstelle noch nicht verifiziert, inaktiv), 2 ENTFERNEN (v5v.in, 72.5.65.111; keine Primärquelle). Aktiv: 57 ip, 12 dom, 21 hash, 22 path. Testlog-Erwartung `ATTACKER_DOM_RE` auf 1 gesetzt (die Testzeilen nutzen gs.thc.org und v5v.in).
**Nachher:** SHA-256 c8c9dd55272157c92afd4a3159a244fcd9e6cada29070bbaf40c54cfe2387a20
**Test (Bearbeiter):** sh -n ok, release.sh IOC-Prüfung ok, --testlog 29 PASS, Fixtures grün
**Bearbeiter:** ceterion AG, Jens Miltenberger

---

## 2026-10-19 - RULES_VERSION 2026-10-19

**Anlass:** Hinweis eines Rechteinhabers (19.10.): Einzelne Indikatorblöcke in einem Community-Checker stammen von Dritten, die sie nur für dieses Werkzeug freigegeben haben. Die Übernahme der Listen am 15.10. (Stand 2026-10-15d) erfolgte auf Basis der MIT-Lizenz des Repos; ceterion verwendet keine Daten, deren Herkunft Dritte beanstanden, unabhängig von der Lizenzlage. Seitdem gilt: Fundstelle beim Erstautor je Wert (Format 2 ab 2026-10-19).
**Entfernt:** alle Werte, die ausschließlich über die betreffenden Blöcke vorlagen (Script-Kommentare als Zuordnung): 35 Adressen aus `ATTACKER_IP_RE`, die gesamte `SCANNER_IP_RE` (93 Adressen) und 18 Hashes aus `PAYLOAD_HASHES`. 18 Werte aus diesen Blöcken sind unabhängig belegt (Unit 42 30.09./01.10., CISA 261399 r1, eigene Primärquellen) und bleiben mit dieser Herkunft.
**Vorher:** 2026-10-16b | **Nachher:** SHA-256 6611ff2010357751b22b5b2a26b3dd57df525be2faac13bf8a832256dfc5c5cf
**Archivierte Regelstände 2026-10-15d bis 2026-10-16b** in `docs/testdata/` gelöscht, weil sie die Daten enthielten; die Präfix-Prüfung läuft ab jetzt gegen 2026-10-19. `docs/checker-diff.sh` und WORKFLOW Schritt 6b entfernt: Der Checker ist Referenz, nicht Datenquelle.
**Test (Bearbeiter):** sh -n ok, --testlog 29 PASS, Fixtures grün
**Bearbeiter:** ceterion AG, Jens Miltenberger

---

---

## Vorgeschichte (Regelstände 2026-10-09 bis 2026-10-16b, nicht mehr verteilt)

Die Regeldatei entstand ab dem 2026-10-09 aus den Citrix-Bulletins CTX697096, CTX697174 und CTX697191, CERT-EU, Mandiant/GTIG, watchTowr, Unit 42, LevelBlue, Sygnia, SOCRadar und der CISA-Regel 261399 (r1). Vom 2026-10-15 bis 2026-10-19 enthielt sie zusätzlich Indikatorlisten aus einem Community-Checker; nach dem Hinweis seines Autors, dass einzelne Blöcke von Dritten nur für dieses Werkzeug freigegeben waren, wurden alle Werte entfernt, die ausschließlich darüber vorlagen (Eintrag 2026-10-19). Seitdem trägt jede Indikatorzeile Quelle, Veröffentlichungsdatum und Fundstelle beim Erstautor (Format 2), und Zusammenstellungen Dritter gelten als Verweis, nicht als Quelle. Die vollständige Entwicklungshistorie dieser Regelstände liegt bei ceterion vor.
