package RuleManage;
use strict;
use IO::File;
use Data::Dumper;
use Switch;
#open rule file
#打开文文件句柄
#diff rule

my $FH;
our %rule;
open($FH,"/home/jcc/Desktop/waf/Waf/Rule/rule") || die "Couldn't open file rule, $!";
if (not defined $FH) {
  print "open rule file error";
}
my $sql_i=0;
my $xss_i=0;
my $dir_i=0;
my $eval_i=0;
while (<$FH>) {
    #split ;
  my @rules = split(/:/,$_);
  chomp $rules[1];
  #$rules[1] = qr/$rules[1]/;
  switch($rules[0]){
    case "SQL" { $rule{'SQL'}[$sql_i] = $rules[1]; $sql_i++; }
      case "XSS" { $rule{'XSS'}[$xss_i] = $rules[1]; $xss_i++;}
      case "Dir" { $rule{'Dir'}[$dir_i] = $rules[1];  $dir_i++; }
      case "EvalCode" { $rule{'EvalCode'}[$eval_i] = $rules[1];  $eval_i++; }
    }
}
close $FH;

#print Dumper %rule;
sub new{
  my $self = shift;
  $self =  bless{}, $self;
  return $self;
}

sub getallrule{
  my $self =shift;
  my $i = 0;
  my @allrule;
  for my $tag (qw/SQL XSS Dir EvalCode/){
  foreach my $val (@{$rule{$tag}}){
    $allrule[$i] =[$tag, qr/$val/];
    $i ++ ;
  }
}
  #my $tagref =  \@{$tag."rule"};
  return @allrule;

}

sub getrule{
  my $self = shift;
  my $tag = shift;
  my $i = 0;
 
  foreach my $val (@{$rule{$tag}}){
     @{$tag."rule"}[$i] = qr/$val/;
    $i ++ ;
  }
  my $tagref =  \@{$tag."rule"};
  return $tagref;
}

sub addrule{
  my $self = shift;
  my $addrule = shift;
 # print Dumper $addrule;
  open(my $DATA,">>/home/jcc/Desktop/waf/Waf/Rule/rule") || die "Couldn't open file rule, $!";
  my @addrules = @{$addrule};
 # print Dumper @addrules;
    for my $i (0..$#addrules){  
      my $aref=$addrules[$i];  
      for my $j (0..$#{$aref}){  
        my $str = $addrules[$i][$j][0].":".$addrules[$i][$j][1]."\n";
        print $DATA $str;
      }  
    } 
  
  close $DATA;
}
sub delcheckrule{
   my $self = shift;
  my @delnums = shift;   
  my @delrules = $self->getallrule();
  foreach my $delnum (@delnums){
	delete $delrules[$delnum];
} 


print Dumper @delrules;
open(my $DATA,">/home/jcc/Desktop/waf/Waf/Rule/rule") || die "Couldn't open file rule, $!";
for my $i (@delrules){
	 my $aref=$delrules[$i];  
      for my $j (0..$#{$aref}){  
        my $str = $delrules[$i][$j][0].":".$delrules[$i][$j][1]."\n";
        print $DATA $str;
      }  
}
}
#传入hash的数组
sub delrule{
  my $self = shift;
  my $delrule = shift;
  #print Dumper $delrule;

  foreach my  $key ( keys %$delrule){
   # print "key".$key;
    foreach my $val(@{$delrule->{$key}}){
      my $i = 0;
      #print Dumper %delrule;
      foreach my $hasval  (@{$rule{$key}}){
        print "$val"."-->".$hasval."\n";
        if ($val eq $hasval) {
          print $val;
          delete $rule{$key}[$i];
        }
        $i++ ;
      }
    }
  }
 #print Dumper $rule{'XSS'};
  open(my $DATA,">rule") || die "Couldn't open file rule, $!";
  for my $key (keys %rule){
    #print "kkkk". Dumper $key;
    foreach my $eachrule (@{$rule{$key}}){
      #print $eachrule."\n";
      my $str =$key.":".$eachrule."\n";
      if($eachrule){
          print $DATA $str;  
      }
    
    }
  
  }
  close $DATA;

}
1;

#
#
#my $test = new RuleManage;
#my %del =(
#          'SQL' => [ q/\w*((%27)|(\'))\w*(and|or)/,
#                     q/((\%27)|(\'))union/,
#                   ]
#                   );
#print Dumper $test->getrule('XSS');
#my @addr = [
#            ['SQL',q/errewr/],
#            ['SQL',q/dfd/],
#           ];
#$test->addrule(\@addr);
#my @delnumm =[1,2];
#$test->delcheckrule(@delnumm);
#print Dumper $test->getallrule();


