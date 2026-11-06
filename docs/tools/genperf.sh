#!/bin/sh
# genperf.sh <zielordner>: synthetische Laufzeit-Fixture (nicht im Repo): 2000 fremde Adressen mit Sondierung und Fehlversuchen,
# 60 Konten mit Erfolgen, rund 50.000 AAA-Zeilen und 20.000 Access-Log-Zeilen im Dokumentationsformat. release.sh misst die Laufzeit.
REPO=$(cd "$(dirname "$0")/../.." && pwd); D="$1"; [ -n "$D" ] || exit 1
rm -rf "$D"; cp -r "$REPO/docs/testdata/fixtures/clean" "$D"
perl -e '
  my @d=("Oct  7","Oct  8","Oct  9"); my $n=100000; my @ok;
  open(N, ">>", "'"$D"'/var/log/ns.log"); open(A, ">>", "'"$D"'/var/log/httpaccess.log");
  for my $di (0..2) { my $dd=sprintf("%02d", 7+$di);
    for my $u (1..60) { for my $k (1..5) { my $hh=8+($k*2)%9; my $mm=($u*7+$k*3)%60; $n++;
      printf N "%s %02d:%02d:00 <local0.info> 192.0.2.5 10/%s/2026:%02d:%02d:00 GMT gw-01 0-PPE-0 : default SSLVPN LOGIN %d 0 : Context user%03d\@203.0.113.60 - SessionId: %d - User user%03d - Client_ip 203.0.113.60 - Nat_ip \"Mapped Ip\" - Vserver 203.0.113.10:443 - Browser_type \"Mozilla\" - SSLVPN_client_type Clientless - Group(s) \"N/A\"\n", $d[$di],$hh,$mm,$dd,$hh,$mm,$n,$u,$n,$u } }
    for my $i (0..1999) { my $ip=sprintf("%d.%d.%d.%d", 100+int($i/65536), 1+int($i/256)%256, 1+$i%256, 10+$di);
      for my $k (1..8) { my $hh=($i*3+$k)%24; my $mm=($i*7+$k*5)%60; $n++;
        printf N "%s %02d:%02d:%02d <local0.info> 192.0.2.5 10/%s/2026:%02d:%02d:%02d GMT gw-01 0-PPE-%d : default AAA LOGIN_FAILED %d 0 :  User acct%05d - Client_ip %s - Nat_ip \"Mapped Ip\" - Vserver 203.0.113.10:443 - Failure_reason \"External authentication server denied access\" - Browser Mozilla\n", $d[$di],$hh,$mm,$k*7,$dd,$hh,$mm,$k*7,$k%4,$n,($i*8+$k)%4000,$ip }
      for my $k (1..3) { my $hh=($i*5+$k)%24; my $mm=($i*11+$k)%60;
        printf A "%s - - [%s/Oct/2026:%02d:%02d:%02d +0200] \"GET /vpn/../vpns/portal/scripts/newbm.pl?x=%d HTTP/1.1\" 404 1234 \"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64)\"\n", $ip,$dd,$hh,$mm,$k,$k;
        printf A "%s - - [%s/Oct/2026:%02d:%02d:%02d +0200] \"GET /cgi/login HTTP/1.1\" 200 512 \"-\" \"Mozilla/5.0\"\n", $ip,$dd,$hh,$mm,$k+30 } } }
  close N; close A;'
touch "$D"/var/log/*; echo "perf fixture: $(wc -l < "$D/var/log/ns.log") ns.log lines, $(wc -l < "$D/var/log/httpaccess.log") access lines"
