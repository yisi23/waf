#!/usr/bin/perl
use Data::Dumper;

my $str = 'form-data; name="userfile"; filename="shell.php"';
my @fields = split /;/, $str;
my %hash;
foreach my $val (@fields){  
  my ($key, $value) = split /\s*=\s*/, $val;
  $key =~ s/^\s+|\s+$//g;
  $value =~ s/^"|"$//g;
  $hash{$key}=$value;
}
print $hash{'filename'}."\n";
print Dumper %hash;

