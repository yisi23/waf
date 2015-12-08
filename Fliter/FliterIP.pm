package FliterIP;
use IpStatus;
#读取black ip list

sub deny_ip{
  my $compare_ip = shift;

  open(my $fh, "<", "/home/jcc/Desktop/waf/Waf/Fliter/ipblacklist") 
    or die "cannot open < ipblacklist: $!";
  #判断是否是有效IP 
  while(<$fh>){
    chomp $_;
    if($compare_ip eq $_){
     return IpStatus::IP_Deny;
   }
  }
  return IpStatus::IP_Allow;
}
1;
