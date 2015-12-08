#!/usr/bin/perl -w
# DirTraversal.pm --- 
# Author: jcc <jcc@jcb>
# Created: 03 Apr 2014
# Version: 0.01
#文件遍历规则
package DirTraversal;

use lib '../Log';
use warnings;
use strict;
use Moose;
#遍历标志  0 无 1攻击
has 'DirTraversalFlag' => (
                           is => 'ro',
                           isa => 'ArrayRef',
                           default => sub{[0,1]},
                          );
#请求IP
has 'requestinfo'=>(
                    is => 'rw',
                    isa => 'Str'
                   );
#定义过滤规则
has 'DirTrav' => (
                  is => 'rw',
                  isa =>'ArrayRef',
                  default =>sub  {[
                                   qr/((%2e%2e%2f)|(%2e%2e\/)|(%2e\.%2f)|(%2e\.\/)|(\.%2e%2f)|(\.%2e\/)|(\.\.%2f)|(\.\.\/))/ix,#匹配（../）及其URL编码
                                   qr/(\/etc\/passwd)/ix,#/etc/passwd linux password文件
                                   qr/((%2e%2e%5c)|(%2e%2e\\)|(%2e\.%5c)|(%2e\.\\)|(\.%2e%5c)|(\.%2e\\)|(\.\.%5c)|(\.\.\\))/ix,
                                   qr/%00/ix,
                                  ]},
                 );
has 'DirTravercheckstr' => (
		is => 'rw',
		isa => 'HashRef',
	);
has 'attacklog' =>(
                   is => 'rw',
                   isa => 'Any',
                  );

sub _dirtrav_fliter{
  my $self = shift;
  for my $x  ( @{ $self->DirTrav } ){
#    foreach  my $key (keys( %{ $self->DirTraversalcheckstr })) {
       my $value =  $self->DirTravercheckstr->{'uri'};
       if(defined $value){
         #log模块
         if ($value =~ /$x/) {
           #Log模块
           print "match $x\n";
           $self->attacklog->LogData->{'attacklog'}="DirTravel ".$self->requestinfo." Rule:".$x;
           $self->attacklog->_record_log;
           return @{$self->DirTraversalFlag}[1];           
         }
       }
 #    }
    return @{ $self->DirTraversalFlag }[0];
  }
}

sub _add_rule{
  my $self = shift;
  my $new_rule =shift;
  unshift( @{$self->DirTraversal} , $new_rule );
}
#################
#sub is_valid_pattern {
 # my( $pattern ) =   ;
  #local( $@ );
##
  #eval { '' =~ /$pattern/ };
#  return defined $@ ? 0 : 1;
#}

##test
#my $DirTraversal_test = new DirTraversal;
#$DirTraversal_test->_dirtrav_fliter;


1;
__END__

=head1 NAME

DirTraversal.pl - Describe the usage of script briefly

=head1 SYNOPSIS

DirTraversal.pl [options] args

      -opt --long      Option description

=head1 DESCRIPTION

Stub documentation for DirTraversal.pl, 

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
