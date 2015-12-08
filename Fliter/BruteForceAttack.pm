#!/usr/bin/perl -w
# BruteForceAttack.pm --- jcb
# Author: jcc <jcc@jcb>
# Created: 29 Mar 2014
# Version: 0.01

use warnings;
use strict;
use Moose;

##############
# 防止暴力攻击 #
#  ip+cookie # 
##############


has 'RequestIp' =>(
                   is => 'ro',#rw 
                   isa => 'Ipv4',
                   #根据_request_one_ip_many 触发DDOS警报
                   handles => {
                               

                              }
                  );
#subtype Ipv4{}
sub  _record_request_ip {
  my $self = shift;
  #记录到数据库
  my $request_ip = shift;
  #DBI->write();

  #分析请求次数

}
sub _request_one_ip_many{
  
}
  
1;
__END__

=head1 NAME

BruteForceAttack.pl - Describe the usage of script briefly

=head1 SYNOPSIS

BruteForceAttack.pl [options] args

      -opt --long      Option description

=head1 DESCRIPTION

Stub documentation for BruteForceAttack.pl, 

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
