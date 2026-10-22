# Normalisierung des Config-Diffs und Plattformregeln

## Diff laufende gegen gespeicherte Config

`show ns runningConfig` und `ns.conf` unterscheiden sich in der Darstellung, nicht im Inhalt. Ohne Normalisierung meldete der erste Lab-Lauf 366 Rauschzeilen. Beide Seiten werden vor dem Vergleich gleich behandelt:

| Regel | Grund |
|---|---|
| Kommentar-, Leer- und ` Done`-Zeilen entfernt | Header, nscli-Abschluss |
| ` -devno N` entfernt | interne Device-Nummer, nur in ns.conf |
| Werte hinter `-keyValue`, `-password`, `-passphrase`, `-ldapBindDnPassword`, `-radKey`, `-sharedSecret` und ähnlichen maskiert | NetScaler verschlüsselt diese Felder bei jeder Ausgabe mit neuem Salt |
| Token nach `-inform PFX` maskiert | ns.conf schreibt die PFX-Passphrase positional ohne Schlüsselwort |
| Hex-Tokens ab 48 Zeichen maskiert | fängt verschlüsselte Werte ohne bekanntes Schlüsselwort; `-CertKeyDigest` (32) bleibt |
| `-inform` in Großschreibung, `-encrypted ... -suffix X` entfernt, Whitespace angeglichen, sortiert | Darstellung und Reihenfolge |

Folge: ein getauschtes Passwort oder ein neuer Schlüssel erscheint nicht im Diff; dafür bleibt `CMD_EXECUTED` in `ns.log`. Jede neue Darstellungsdifferenz auf anderen Builds wird eine eigene Regel, kein Pauschalfilter.

## Plattformregel: NetScaler /bin/sh

Das FreeBSD-`sh` auf NetScaler 14.1 stürzt mit SIGSEGV ab, wenn eine Klammergruppe als Pipeline-Anfang in einer Command Substitution steht:

```sh
X=$( { cmd1; cmd2; } | sort )     # Absturz des Interpreters, Exit 139
```

Ersatz: Ausgaben in eine temporäre Datei schreiben und von dort lesen. Diagnose bei Abstürzen immer mit `sh -x script 2>/tmp/trace.txt`; die Meldung "Segmentation fault" schreibt die interaktive Shell auf das Terminal, nicht in eine Pipe, deshalb findet `2>&1 | grep` sie nicht.

Weitere Beobachtungen aus dem Lab (14.1-73.41): `stat responder policy <name>` ignoriert den Namen und kürzt Namen auf zwölf Zeichen (Hits deshalb aus `show responder policy <name>`); `ns.log` enthält den Shell-Audit `sh_command="..."` nach local6 und die `ps`-Ausgabe von `nsprofmon_mgmt.pl`; `httpd.conf` hat `AddType application/x-httpd-php` global und elf `Alias /vpns/...` auf `/var/ns_gui` und `/netscaler/portal`; php-fpm lauscht auf 127.0.0.1:9999 und ein Python-Dienst auf 127.0.0.1:29000.

## Ergänzung 2026-10-14: jede Klammergruppe in einer Kommandosubstitution

Zweiter Absturz derselben Klasse, gefunden mit dem Fixture-Lauf auf einer Appliance: nicht nur `$( { ...; } | ... )`, sondern jede Klammergruppe `{ ...; }` innerhalb von `$( )` stürzt die NetScaler-`sh`, auch in der Mitte einer Pipeline (`$(a | { if ...; fi; } | b)`). Das Konstrukt stand seit Quickcheck 10.0 in der System-User-Prüfung und lief bis 12.0 nur offline auf Linux, wo es funktioniert.

Regel: keine `{ ... }` in `$( )`. Ersatz: Funktion definieren und in der Pipeline aufrufen, oder `grep -v` mit Default-Wert (`grep -vxF -- "${VAR:-platzhalter}"`), oder Zwischendatei in `$WORK`.

`docs/release.sh` prüft das per Lint (awk, verfolgt die Tiefe von `$( )` und meldet eine Klammergruppe bei Tiefe größer null; `|| { ... }` hinter einer geschlossenen Substitution ist erlaubt). Derselbe Lauf hat den nie ausgeführten mktemp-Fallback aus 1.0 gefunden, der dieselbe Form hatte. Ein Fixture-Lauf auf Linux ersetzt die NetScaler-Shell nicht: jede Script-Version muss einmal auf einer Appliance laufen, online und mit `--from`, bevor sie als validiert gilt.

## BSD-sed und \t

Die `sed` der NetScaler-Shell (FreeBSD) kennt `\t` weder im Muster noch in der Ersetzung; `sed 's/^/B\t/'` schreibt `Bt`. Am Arbeitsplatz mit GNU sed fällt das nicht auf. Gefunden am 2026-10-21: Die kumulierte Adressliste blieb auf der Appliance leer, die "Verwundbar"-Zeilen fehlten im JSON. Regel: Tabulatoren mit `awk '{ printf "B\t%s\n", $0 }'` oder `printf` erzeugen, nie mit sed; `docs/release.sh` lehnt `sed` mit `\t` ab (Plattform-Lint 2).

## BWK-awk und Intervalle

Das `awk` der NetScaler-Shell ist das FreeBSD-awk (BWK, "one true awk") in einem Stand, der Intervall-Ausdruecke `{n,m}` in regulaeren Ausdruecken nicht kennt; `[0-9]{1,2}` trifft dort nie. gawk und mawk am Arbeitsplatz koennen es. Gefunden am 2026-10-21: Das Datum der letzten Beobachtung blieb leer, gesperrte Adressen wurden faelschlich als "Sperre greift nicht" gemeldet. Regel: in awk-Programmen nur `+`, `*`, `?` und ausgeschriebene Wiederholungen; Datumsparsing in perl. `docs/release.sh` lehnt Intervalle in awk-Programmen ab (Plattform-Lint 3). In `grep -E` und `perl` sind Intervalle erlaubt.
