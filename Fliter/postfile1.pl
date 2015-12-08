#!/usr/bin/perl -w
# postfile.pl --- jcb
# Author: jcc <jcc@jcb>
# Created: 01 May 2014
# Version: 0.01

use warnings;
use strict;
use LWP::UserAgent;
use LWP;
use HTTP::Request::Common;

my  $ua = LWP::UserAgent->new;;
my $res = $ua->request(POST 'http://localhost:12345',
			Content_Type => 'form-data',
			Content => [	
            				userfile => ["shell.php", "shell.php"],
				   ],

);
print $res->as_string();

__END__

=head1 NAME

postfile.pl - Describe the usage of script briefly

=head1 SYNOPSIS

postfile.pl [options] args

      -opt --long      Option description

=head1 DESCRIPTION

Stub documentation for postfile.pl, 

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
