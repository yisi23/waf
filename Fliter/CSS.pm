#!/usr/bin/perl -w
# CSS.pm --- jcb
# Author: jcc <jcc@jcb>
# Created: 02 Apr 2014
# Version: 0.01
package CSS;

use warnings;
use strict;

use Moose;
has 'XssRuleFlag'=>(
                    is => 'ro',
                    isa => 'ArrayRef',
                    default =>sub{[0,1]},
                   );
has 'XSS_Rule' =>(
                  is => 'rw',
                  isa =>'ArrayRef',
                  default => sub{[
                                  qr/((%3C)|<) ((%2F)|\/) * [a-z0-9%]+ ((%3E)|>)/ix,#/ix,<script> </script>
                                  qr/((%3C)|<) ((%69)|i|(%49)) ((%6D)|m|(%4D)) ((%67)|g|(%47)) [^\n]+ ((%3E)|>)/ix,#//ix <img src
                                  #'',#过滤关键字
                                 ]},
                 );

has 'xsscheckstr' =>(
                     is => 'rw',
                     isa => 'HashRef',
                    );
has 'requestinfo' =>(
                     is => 'rw',
                     isa => 'Str',
                    );
has 'attacklog' =>(
                   is => 'rw',
                   isa => 'Any',
                  );
sub _xss_fliter{
  my $self = shift;
  for my $x ( @{ $self->XSS_Rule} ) {
    foreach  my $key ( keys(%{ $self->xsscheckstr })) {
      my $value=  $self->xsscheckstr->{$key};
      if (defined $value){
        if($value =~ /$x/){
          #Log模块
          print  "match rules: $x\n";
          $self->attacklog->LogData->{'attacklog'}="CSS ".$self->requestinfo." Rule:".$x;
          $self->attacklog->_record_log;
          return @{$self->XssRuleFlag}[1];
        }
      }
    }
    return @{ $self->XssRuleFlag }[0];
  }
}
#添加规则
sub _add_rule{
  my $self = shift;
  my $new_rule = shift;
  unshift( @{ $self->XSS_Rule },$new_rule);
}

#test
#my $test = new CSS;
#print @{$test->XssRuleFlag}[1];

1;
__END__

=head1 NAME

CSS.pl - Describe the usage of script briefly

=head1 SYNOPSIS

CSS.pl [options] args

      -opt --long      Option description

=head1 DESCRIPTION

Stub documentation for CSS.pl, 

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
