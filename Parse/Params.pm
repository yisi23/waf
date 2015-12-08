package HTTP::Request::Params;
# $Id: Params.pm,v 1.1 2005/01/12 16:42:32 cwest Exp $
use strict;

=head1 NAME

HTTP::Request::Params - Retrieve GET/POST Parameters from HTTP Requests

=head1 SYNOPSIS

  use HTTP::Request::Params;
  
  my $http_request = read_request();
  my $parse_params = HTTP::Request::Params->new({
                       req => $http_request,
                     });
  my $params       = $parse_params->params;

=cut

use vars qw[$VERSION];
$VERSION = sprintf "%d.%02d", split m/\./, (qw$Revision: 1.1 $)[1];

use CGI;
use Email::MIME::Modifier;
use Email::MIME::ContentType qw[parse_content_type];
use HTTP::Request;
use HTTP::Message;
use base qw[Class::Accessor::Fast];

=head1 DESCRIPTION

This software does all the dirty work of parsing HTTP Requests to find
incoming query parameters.

=head2 new

  my $parser = HTTP::Request::Params->new({
                  req => $http_request,
               });

C<req> - This required argument is either an C<HTTP::Request> object or a
string containing an entier HTTP Request.

Incoming query parameters come from two places. The first place is the
C<query> portion of the URL. Second is the content portion of an HTTP
request as is the case when parsing a POST request, for example.

=head2 params

  my $params = $parser->params;

Returns a hash reference containing all the parameters. The keys in this hash
are the names of the parameters. Values are the values associated with those
parameters in the incoming query. For parameters with multiple values, the value
in this hash will be a list reference. This is the same behaviour as the C<CGI>
module's C<Vars()> function.

=head2 req

  my $req_object = $parser->req;

Returns the C<HTTP::Request> object.

=head2 mime

  my $mime_object = $parser->mime;

Returns the C<Email::MIME> object.

Now, you may be wondering why we're dealing with an C<Email::MIME> object.
The answer is simple. It's an amazing parser for MIME compliant messages,
and RFC 822 compliant messages. When parsing incoming POST data, especially
file uploads, C<Email::MIME> is the perfect fit. It's fast and light.

=cut

sub new {
    my ($class) = shift;
    my $self = $class->SUPER::new(@_);

    $self->req(HTTP::Request->parse($self->req))
      unless ref($self->req);

    my $message = (split /\n/, $self->req->as_string, 2)[1];
    $self->mime(Email::MIME->new($self->req->as_string));

    $self->_find_params;

    return $self;
}
__PACKAGE__->mk_accessors(qw[req mime params]);

sub _find_params {
    my $self = shift;
    my $query_params = CGI->new($self->req->url->query)->Vars;
    my $post_params  = {};

    if ( $self->mime->parts > 1 ) {
        foreach my $part ( $self->mime->parts ) {
            next if $part == $self->mime;
            $part->disposition_set('text/plain'); # for easy parsing

            my $disp    = $part->header('Content-Disposition');
            my $ct      = parse_content_type($disp);
            my $name    = $ct->{attributes}->{name};
            my $content = $part->body;

			$content =~ s/\r\n$//;
            $self->_add_to_field($post_params, $name, $content);
        }
    } else {
    	chomp( my $body = $self->mime->body );
        $post_params = CGI->new($body)->Vars;
    }

    my $params = {};
    $self->_add_to_field($params, $_, $post_params->{$_})
      for keys %{$post_params};
    $self->_add_to_field($params, $_, $query_params->{$_})
      for keys %{$query_params};
    $self->params($params);
}

sub _add_to_field {
    my ($self, $hash, $name, @content) = @_;
    my $field = $hash->{$name};
    @content = @{$content[0]} if @content && ref($content[0]);
	@content = map split(/\0/), @content;

    if ( defined $field ) {
        if ( ref($field) ) {
            push @{$field}, @content;
        } else {
            $field = [ $field, @content ];
        }
    } else {
        if ( @content > 1 ) {
            $field = \@content;
        } else {
            $field = $content[0];
        }
    }
    $hash->{$name} = $field;
}

1;

__END__

=head1 SEE ALSO

C<HTTP::Daemon>,
L<HTTP::Request>,
L<Email::MIME>,
L<CGI>,
L<perl>.

=head1 AUTHOR

Casey West, <F<casey@geeknest.com>>.

=head1 COPYRIGHT

  Copyright (c) 2005 Casey West.  All rights reserved.
  This module is free software; you can redistribute it and/or modify it
  under the same terms as Perl itself.

=cut
