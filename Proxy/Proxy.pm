#!/usr/bin/perl
package Proxy;
use LWP::UserAgent;
use LWP::ConnCache;
use IO::Socket;

my $agent;
my $request_str;
my $timeout;
my $response;

#判断root


sub new{
  my $class  = shift;
  $request_str = shift;
  my $self = bless {},$class;
  $agent = $self->_init_agent();
  return $self;
}

#初始化代理引擎
sub _init_agent{
  my $self = shift;
  my $agent = LWP::UserAgent->new(
                                  env_proxy  => 1,
                                  keep_alive => 2,
                                  parse_head => 0,
                                  timeout    => 10,
                               )
    or die "Cannot initialize proxy agent: $!";
  $agent->protocols_allowed( [ 'http', 'https'] ); 
  return $agent;
}

#请求object
sub _request_object{
  my $self = shift;
  my $requestObj = HTTP::Request->parse( $request_str );
  return $requestObj;
}

sub _get_response{
  my $self  = shift;
  my $upstream;
  my $last = 0;
 #   print $self->{"ForwardIP"};
  my $requestObj = $self->_request_object();

  
  my $response = $agent->simple_request($requestObj);
  
  # check the upstream proxy's response
  my $code = $response->code;

  if ( $code == 407 ) {    # don't forward Proxy Authentication requests

    # clean up authentication info from proxy URL
    $up =~ s{^http://[^/\@]*\@}{http://};
 
    my $response_407 = $response->as_string;
    $response_407 =~ s/^Client-.*$//mg;
    $response = HTTP::Response->new(502);
    $response->content_type("text/plain");
    $response->content( "Upstream proxy ($up) "
                        . "requested authentication:\n\n"
                        . $response_407 );
    $self->response($response);
  }
  elsif ( $code != 200 ) {    # forward every other failure
    $self->{"response"}  = ($response);
   # print "res";
  }
  #$response->decoded_content;
  # print "response success";
  return $response;
  
}

#攻击回应包
sub _attack_response{
  my $self = shift;
  my $response_attack;

  $response_attack = HTTP::Response->new(200);
  $response_attack->header( "Server" => 'jcb waf/1.0');
  $response_attack->content_type("text/plain");
  $response_attack->content("attack data!!!");

  $self->{'response'} = $response_attack;
  #print $response_attack->content;
  return $self->{'response'};
}

1;
