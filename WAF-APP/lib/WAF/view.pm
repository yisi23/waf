package view;
use Logfile::Tail;
use Data::Dumper;

sub getlog{
  
  system(`tail --lines=15 /home/jcc/Desktop/waf/Waf/Log/sys.log > /home/jcc/Desktop/waf/Waf/Log/tmp.txt`);
  open ( my $data ,'/home/jcc/Desktop/waf/Waf/Log/tmp.txt');
  my @log;
  my $i = 0;
  while(<$data>){
    $log[$i] = $_;
    $i++;
  }
  return \@log;
}

#print Dumper &getlog;
1;

