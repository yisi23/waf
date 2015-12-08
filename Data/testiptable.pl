#!/usr/bin/perl
my $ip="1.1.1.1";
my $ru = "iptables -D INPUT -s 1.1.1.3 -j DROP";
system("iptables -A INPUT -s $ip -j DROP");
system("at now +1 minutes <<END
$ru
<<END
");
