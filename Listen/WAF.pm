package WAF;
#------------------------------------
# Author: jcc <jcc@jcb>
# Created: 01 May 2014
# Version: 0.01
use lib 'Listen';
use warnings;
#!usr/bin/perl -w 

sub run{
 # $pid=fork(); #复制进程，并把返回值附入$pid 
  #die "Error:$!n" unless defined $pid; 
  #制定程序的错误机 制，此步可略 
  #if($pid!=0){ #条件选择，测试$pid值 
    #print"This is a main pid!PID is $$!n"; #$pid值不等于0，此为父进程(附:$$为保留变量，其值为此进程的PID)
  # }else{ #否则..... 
     use  AcceptData;
     AcceptData::runlisten;
     #print"This is a sub pid!PID is $$!n"; #$pid值为0，此为子进程 
 # }
}

# is root
#get current username
sub getusername{
  my $username = $ENV{LOGNAME} || $ENV{USER} || getpwuid($<);
  if ($username eq "root") {
    return 1;
  }else{
    die "you need root to run\n";
    return 0;
  }
}



1;
__END__

=head1 NAME

run.pl - Describe the usage of script briefly

=head1 SYNOPSIS

run.pl [options] args

      -opt --long      Option description

=head1 DESCRIPTION

Stub documentation for run.pl, 

=head1 AUTHOR

jcc, E<lt>jcc@jcbE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2014 by jcc

This program is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.2 or,
at your option, any later version of Perl 5 you may have available.

=head1 BUGS

None reported... yet.

=cut
