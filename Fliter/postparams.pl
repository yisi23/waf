#!/usr/bin/perl 
use URI;
use LWP::UserAgent;
my $browser = new LWP::UserAgent;
  my $url = URI->new( 'http://localhost:12345' );
    # makes an object representing the URL
  
  $url->query_form(  # And here the form data pairs:
    'title'    => 'Blade Runner',
    'restrict' => 'Movies and TV',
  );
  
  my $response = $browser->post($url);
