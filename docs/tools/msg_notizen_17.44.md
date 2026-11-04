# msg_notizen.md - Nachrichtenkataloge netscaler-quickcheck 17.43

Stand 2026-10-29. Grundlage: `ns_quickcheck.sh` Version 17.43 (2084 Zeilen). 491 Keys, 536 Fundstellen in `ns_quickcheck.msgmap.tsv`.

Automatisch geprueft: Jeder deutsche Katalogtext wurde segmentweise gegen seine Fundstelle im Script verglichen (Text zwischen den Platzhaltern muss in dieser Reihenfolge in der Zeile stehen). Dazu die Pruefungen aus Punkt 8 (Key-Mengen gleich, jeder Key einmal, genau ein Tab, gleiche Platzhalter je Key, keine Geviert- oder Halbgeviertstriche). Alle bestanden.

## 1. Auffaelligkeiten im deutschen Text (nicht korrigiert)

| Zeile | Key | Auffaelligkeit |
|---|---|---|
| 1410 | TRACE_BLOCKED_NODATE_FRAG | `${_s:-, ohne Datum}` gibt bei gesetztem Datum das Datum ein zweites Mal aus. Ergebnis: "ja, Sperre ab 2026-10-202026-10-20". Ohne Datum korrekt "ja, ohne Datum". |
| 1961 | VERDICT_UPDATE_SAML | `$FIXB` ist im Script nirgends gesetzt, Ausgabe "Ziel: 14.1-.". Ausserdem endet %1 durch `tr '\n' ' '` mit Leerzeichen: "(siehe Block 1: CVE-2026-88779 )". |
| 1973 | VERDICT_INV_NO_MITIG | Bedingung `VULN -eq 1` im INVESTIGATE-Zweig, der nur bei VULN=0 erreicht wird. Die Zeile wird nie ausgegeben. |
| 1230, 1231 | TRACE_INJ_TODO_FETCH_LOG_DET, TRACE_INJ_TODO_RESP_AUDIT_DET | Ohne Download-Host faellt Zeile 1229 weg; der Zu-tun-Block beginnt dann mit einer Fortsetzungszeile ohne Label "Zu tun:". |
| 1158, 1331, 1389, 1393 | TRACE_INJ_COVERED_TODO_DET u. a. | "Zu tun:" ohne Spaltenauffuellung, sonst "Zu tun:" auf 15 Zeichen. Gleicher Inhalt wie Zeile 1226 ("nichts; der naechste Lauf ...") steht in 1389 mit anderer Auffuellung; dadurch zwei Keys (TRACE_TODO_NOTHING_BLOCK_DET, TRACE_DROP_COVERED_TODO_DET). Ebenso ohne Auffuellung: "Was passiert ist:" (1330, 1771), "Unkritisch wenn:" (1772). |
| 409, 413 | ERR_OPT_UNKNOWN, ERR_HOURS_NOT_NUMBER | stderr ohne Praefix "ERROR:", anders als alle uebrigen Abbruchmeldungen. |
| 858, 904 | ERR_KIB_* | Praefix "ABBRUCH:" statt "ERROR:". |
| 939, 1065, 1066, 1323, 1394, 1404, 1531 | diverse | Text klebt direkt am Platzhalter ("%1(README 15)", "%1- bis zum Update", "%1nur interne Adressen"); funktioniert nur, weil der Wert mit Leerzeichen endet. Beim Umbau Werte unveraendert uebergeben. |
| 1200 | ADDR_SRC_RESPONDER_LINE | Mischsprache "ns.log Responder-Zeile from IP". |
| 926, 1206, 1670 | HDR_TRUSTED_LIST u. a. | "bleiben Rot" / "waere wieder Rot" meint die Kennung [ROT]; im Text aber als Wort. In EN als "red" uebernommen. |

## 2. Kopplungen: Script parst eigene Ausgabetexte

Diese Stellen muessen vor dem Aktivieren von EN umgebaut werden, sonst bricht Logik oder Anonymisierung. Reihenfolge nach Schwere.

1. **Zeile 649 (anon_apply)** entfernt `[Bemerkung: ...]` per Regex. EN-Texte nutzen `[Note: ...]` (TRUST_NOTE_FRAG, TRUST_ACTIVE_TRU, AAA_SLEEPER_ROW, AAA_SPRAY_ROW, AAA_OWN_ROW). Ohne Anpassung bleiben Bemerkungen der Sperr- und Vertrauensliste sowie Kontenlisten in den anon-Fassungen stehen. Datenschutzrelevant.
2. **Zeile 2026** liest `SINCE` aus der Kopfzeile der kumulierten Adressliste ueber das Wort "seit" (ADDR_CUM_HEAD1). EN "since" wird nicht gefunden, das Startdatum wird jeden Lauf neu gesetzt.
3. **Zeile 1217** wertet `passt zu N von M` aus TRACE_INJ_SRC_MATCH_FRAG per grep und Feldposition aus (Kennzeichnung ", schwach").
4. **Zeilen 1212, 1411** schneiden die Quelle aus TRACE_IOC_SOURCE_FRAG per `${_rs#* - Quelle: }`.
5. **Zeile 1510** liest die Anzahl per `grep -oE '[0-9]+ Request'` aus TRACE_MGMT_ADDR_FRAG (EN "request" klein, Treffer leer).
6. **Zeile 1529** liest die Anzahl per `grep -oE '[0-9]+ Fehl'` aus TRACE_SSH_FAIL_FRAG.
7. **Zeile 572 ANON_RESERVED** listet deutsche Reportwoerter (GELB, ROT, HINWEIS, bis, ab, seit, neu, ja, nein ...). Fuer EN fehlen u. a. NOTE, until, since, new, yes, no, from.
8. **Zeile 895** schneidet das KI-Bundle an `### BLOCK 2` / `### BLOCK 3`. Die EN-Koepfe behalten diese Praefixe, daher unkritisch, aber nicht aendern.
9. **Persistente Dateien**: `ns_quickcheck_observed_ips.tsv` behaelt die Spalte beobachtung (ADDR_SRC_*) vom ersten Lauf. Bei Sprachwechsel entstehen gemischte Dateien. Gleiches gilt fuer die JSON-Befundtexte (`red`, `yellow`, Praefix BUILD_VULN_JSON_PREFIX), die bisher deutsch sind.

## 3. Offene Entscheidungen

1. **Zusaetzliche Bloecke TLOG und KIB.** `--testlog` und `--ki-bundle` passen in keinen vorgegebenen Block. Empfehlung: so lassen. Alternative: TLOG unter CHECK, KIB unter HDR. Umbenennen ist reine Suchen/Ersetzen-Arbeit in allen drei Dateien.
2. **ERR enthaelt alle stderr-Ausgaben**, auch Nicht-Fehler (ERR_ANON_SUMMARY, ABBRUCH-Meldungen).
3. **Layout nicht im Katalog:** Detailpraefix `          | ` (in der msgmap als Funktion `det`), Rahmen `== %1 ==` von hdr, Auffuellung hinter den Kennungen. Die EN-Kennungen sind laenger ([YELLOW] 8 Zeichen statt [GELB] 6), die Auffuellung muss das Script aus der Laenge berechnen. Die Labels (Wann:, Zu tun:, Ergebnis:, Quelle: ...) stehen im Text; EN ist auf dieselbe Breite von 15 Zeichen aufgefuellt, Fortsetzungszeilen beginnen mit 15 Leerzeichen.
4. **printf-Breiten** (`%-16s`, `%4d`, `%-14s` in Testlog-, AAA- und Adresszeilen) sind als `%n` abgebildet. Das Script muss die Werte vor dem Einsetzen auf Breite bringen.
5. **Fragmente (_FRAG):** Teilsaetze, die das Script anhaengt. Fuehrende Leerzeichen, Kommas und Semikolons gehoeren zum Wert. Abschliessende Trenner stehen nicht im Katalog und muessen vom Script kommen: Leerzeichen nach `[entfernt]`, `[neu]`, `[nur gespeichert]`, `[nur laufend]`, `Verwundbar:`, `Eskalation:`; `; ` nach TRACE_CRASH_TRIG_FRAG und HDR_CVE_CONFLICT_*_FRAG.
6. **Gemeinsame Kurzwerte:** TRACE_YES/TRACE_NO (ja/nein) und CHECK_UNKNOWN (unbekannt) werden blockuebergreifend genutzt (Vorgabe "gleicher Text, ein Key").
7. **TSV-Spaltennamen** (kategorie, adresse, anzahl_zuletzt ...) bleiben in den EN-Koepfen als Bezeichner unveraendert. Nicht im Katalog: Spaltenkopf der Share-Datei (Zeile 2073, enthaelt Tabs) und die Datenwerte ja/nein der Share-Spalte regeldatei (Zeile 2076), weil das Datenformat der Datei fuer ceterion ist.
8. **Beobachtungstexte ADDR_SRC_*** (ip_note) sind aufgenommen, weil sie im [TRUST]-Block des Reports erscheinen. Wer sie in den TSV-Dateien deutsch halten will, braucht getrennte Werte fuer Report und Datei.
9. **[Bemerkung: ...] / [Note: ...]**: setzt Punkt 2.1 voraus. Alternative ohne Codeaenderung waere ein sprachneutraler Marker in beiden Katalogen.
10. **Key-Zuschnitt Abstuerze:** Im Script sind Kopf (`_hd`, Zeile 1312) und Begruendung (`_why`) getrennt. Daher TRACE_CRASH_HEAD plus TRACE_CRASH_RED / TRACE_CRASH_YEL (`%1 - %2`) statt eines Keys wie im Beispiel der Vorgabe.
11. **Howto-Titel** (Howto Responder-Quelle, Howto Feldbefund, Howto Lockout, Howto Whitelist) sind in EN unveraendert, weil es Dokumentverweise sind. Bei einem englischen README anpassen.
12. **TAG_ACTION / TAG_RESULT** enthalten nur `ACTION` bzw. `RESULT`; Doppelpunkt und Wert setzt das Script.

## 4. Bewusst nicht erfasst

- `--help`: gibt Kommentarzeilen des Scripts aus (Zeile 408), keine Katalogtexte.
- `--version` (Zeile 407): nur Name und Versionsnummer.
- RESULT-Zeile und ihre Feldnamen, JSON-Schluessel, Kategorienamen, Dateinamen, Regex-Muster.
- Interne Zwischenzeilen in `cve.txt` (OPEN, NA, SKIP, ISN, SAMLOPEN, MITIG_OK, `__keins__`). Ausgegebene Teile davon sind als Fragment erfasst (BUILD_CVE_PENDING_FRAG, BUILD_CVE_FIX_INVALID_FRAG, BUILD_CVE_COND_FRAG). Der NA-Text "(Bedingung nicht konfiguriert)" (Zeile 1000) wird nie ausgegeben.
- Texte aus der Regeldatei (CVE-Beschreibungen, BUILD_WARN_13_1) und der Marker ` [custom]` (Zeile 455).
- CLI_REASON "offline" (Zeile 822): wird nur online angezeigt, also nie.
- Technische Objektbezeichner in `own_ips.txt` (ns ip, server, serverIP; Zeilen 1542 bis 1546). Nur "HA-Peer" ist als AAA_OWN_HAPEER erfasst.
- Reine Formatzeilen ohne Woerter (`%1 (%2x)`, `, global %1`, ` (ns.conf: %1)`, `console:`).

## 5. Unsicher zugeordnete Zeilen

| Zeile | Key | Unsicherheit |
|---|---|---|
| 1517 bis 1533 | TRACE_SSH_*, TRACE_AUTH_* | SSH-Anmeldungen (auth.log) unter TRACE einsortiert; AAA nur fuer Gateway-AAA (ns.log). |
| 1325 | TRACE_CRASHFILE_HEAD | Kopf von `ns_quickcheck_observed_crashes.tsv` unter TRACE, nicht ADDR. |
| 648 | HDR_ANON_COMMENT_REMOVED | Ersatztext im `--anon`-Dateimodus; unter HDR, weil kein passender Block existiert. |
| 810 | TRUST_NOTE_FRAG | `[Bemerkung: ...]` auch in blocked_tag (Sperrliste); ein Key fuer beide Listen. |
| 1531 | TRACE_SSH_INTERNAL_ONLY | %1 ist eine awk-Liste "konto (n) ..." mit Leerzeichen am Ende, das Wort `console:` bleibt technischer Bezeichner. |
| 2079 | FOOT_FILES | Abschliessende Dateihinweise auf dem Terminal unter FOOT. |

## 6. Hinweis zur msgmap

Spalte "Funktion" nennt den Ausgabeweg, nicht die umgebende Shell-Funktion: `out`, `out[TAG_INFO]` / `out[TAG_WARN]` (Kennung steht heute im Text und wird beim Umbau zum Key), `det` (out mit Detailpraefix), `inf`, `grn`, `flag_red`, `flag_yel`, `flag_org`, `flag_tru`, `hdr`, `red` / `yel` / `org` / `tru` (Kennungsdefinition), `echo`, `echo>&2`, `echo>file`, `printf`, `awk`, `perl`, `sed`, `assign` (Variablenzuweisung), `ip_note`, `trust_event`. Mehrere Keys auf einer Zeile ergeben mehrere Zeilen. Der Ausschnitt in Spalte 4 ist der deutsche Katalogtext mit Platzhaltern.

## Ausserhalb des Auftrags (nur Hinweis, keine Aenderung)

Zeile 1920: Die Compare-Liste stellt `NEU<TAB>` bzw. `GEAENDERT<TAB>` vor den Pfad und filtert erst danach mit der Whitelist. Auf `^/` verankerte webfile-Regeln greifen dort nicht.
