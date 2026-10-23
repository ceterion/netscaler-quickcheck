# ns_quickcheck.rules - Änderungshistorie

Ein Eintrag je Änderung ab dem ersten veröffentlichten Regelstand (2026-10-19), neueste oben; die Entwicklungsphase davor steht am Ende als Vorgeschichte. Oberer Teil: Anlass und Belege (von Bearbeiter oder KI-Vorschlag). Unterer Teil: Test, Verteilung, Bearbeiter (immer vom Bearbeiter). Format und Pflegeprozess: `ns_quickcheck_README.md`, Abschnitt 7.

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
