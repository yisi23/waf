package ParseData;
#解析Http数据报文
#根据RFC 2616
#.............................
#    1.读取Request_line到缓冲区
#    2.解析数据 waf_http_parse_request_line() 
# ..........................
#--------------------------------------------------------------
#Request       = Request-Line           
#                        *(( general-header        
#                         | request-header         
#                         | entity-header ) CRLF)  
#                        CRLF
#                        [ message-body ]          
#---------------------------------------------------------------
#

use lib '/home/jcc/Desktop/waf/Waf/Fliter';
use lib '/home/jcc/Desktop/waf/Waf/Proxy/';
use lib '/home/jcc/Desktop/waf/Waf/Log';
use strict; 
use HTTP::HeaderParser::XS;
use HTTP::Parser::XS qw(parse_http_request);
use Moose;
use ParseStatus;
use FliterMoudle;
use Proxy;
use Data::Dumper;
use HTTP::Request::Params;

has 'http_lines' =>(
                    is => 'rw',
                    isa => 'Any',
                   );
#解析http请求
sub waf_http_parse_request_line{
    #读取到缓存区数据
    my $self = shift;

    #re_http_lines obj 
    my $re_http_lines = $self->http_lines->{'RequestHeader'};
    #解析请求体，写入hash
    
    my %env;
    my $r = HTTP::Request->parse( $re_http_lines );
    my $hdr = HTTP::HeaderParser::XS->new(\"$re_http_lines");
    my $ret = parse_http_request(
                                 $re_http_lines,
                                 \%env,
                                );
    #转发数据模块  
    my $forward_moudle = new Proxy($re_http_lines);
    
    if ($ret == -2) {
      # request is incomplete
      print "incomplete";
      return ParseStatus::W_Incomplete;
      #数据未完成
    } elsif ($ret == -1) {
      # request is broken
      print "broken";
      return ParseStatus::W_Broken; 
      #数据异常丢包
    } else {

      my $method = $r->method;
      my $geturi = $r->uri->path_query;
      my $host = $r->header( 'Host' ) ;
      my $cookie = $r->header('Cookie') ;	
      #my $accept = $hdr->getHeader('Accept') ;
      my $useragent = $r->header('User-Agent');
      #print Dumper $r->parts;
    
      my %content_ref;
      my  $filecontent;
      my $filename;
      my %fliterstr;
      #获取上传文件内容
      if ($r->content_type eq 'multipart/form-data') {
        if ( defined $r->content && $method eq 'POST' ){
          if (  defined  $r->parts->{'_headers'}->{'content-disposition'} ){
            #获取上传文件名字&&内容
            my  $str=$r->parts->{'_headers'}->{'content-disposition'} ;
            my @fields = split /;/, $str;
            my %hash;
            foreach my $val (@fields){  
              my ($key, $value) = split /\s*=\s*/, $val;
              $key =~ s/^\s+|\s+$//g;
              #$value =~ s/^"|"$//g;
              $hash{$key}=$value;
            }
            $filename =  $hash{'filename'};
            $filename =~  s/^"|"$//g;
            
            my $file_content_type = $r->parts->{'_headers'}->{'content-type'};

            #decode content
            if  ( $r->decode  ) {
              $filecontent = $r->decoded_content;
              
            }else{
              $filecontent =  $r->parts->{'_content'}; 
            }
            
         
            #print Dumper $r->content;
            #fliter str 
            %fliterstr = (
                          #Method => $method,
                          #Host => $host,
                          uri => $geturi,
                          UserAgent => $useragent,           
                          Cookie => $cookie,
                          filename => $filename,
                          filecontent => $filecontent,
                          filetype => $file_content_type,
                         );
          }
        }
      }else{
        %fliterstr = (
                      #Method => $method,
                      #Host => $host,
                      uri => $geturi,
                      UserAgent => $useragent,           
                      Cookie => $cookie,
                      content => $r->content,
                     );
      }
        
      if( $method eq 'GET') {
        #fliter str 
        %fliterstr = (
                         #Method => $method,
                         #Host => $host,
                         uri => $geturi,
                         UserAgent => $useragent,           
                         Cookie => $cookie,
                         #content => $content,
                        );
      }

      
      #print Dumper %fliterstr;

      ##错误 数据
      my $requestinfo = $self->http_lines->{'RequestInfo'}." ".$r->uri;
      my $ev_fliter = new FliterMoudle(
                                       checkstr => \%fliterstr,
                                       requestinfo => $requestinfo,
                                      );
      ##检测模块
      if ($ev_fliter->_check_attack == AttackStatus::NoAttack) {
        #转发数据
        my $forwardinfolog = new LogData();
        $forwardinfolog->LogData->{'flagtype'} = "FORWARD_LOG";
        $forwardinfolog->record_open_file;
        $forwardinfolog->LogData->{'forwardlog'} = $requestinfo." ".$r->uri;
        $forwardinfolog->_record_log;
        return  $forward_moudle->_get_response();
      } else{
        #回应攻击包，或丢弃
        return $forward_moudle->_attack_response;
      }
      #非GET POST方法
      # Method         = "OPTIONS"
      #                | "GET"    
        #                | "HEAD"   
      #                | "POST"   
      #                | "PUT"    
      #                | "DELETE" 
      #                | "TRACE"  
      #                | "CONNECT"
      #                | extension-method
      #不常用的方法
      #   return $self->W_Other_M;
      # }
    }
  }

sub _init_fliter{
    my  $fliter_str = shift;
    my  $flitermoudle = new FliterMoudle( checkstr => $fliter_str);
    return $flitermoudle->_check_attack();
}


sub _init_forward{
  my $forward_request = shift;
  my $waf_forward = new Proxy(
                              $forward_request
                             );
  return $waf_forward;
}


#获取文件名字
sub getfilename{
  my $self = shift;
  my $str = shift;

  print $str;
  
  my @fields = split /;/, $str;
  my %hash;
  foreach my $val (@fields){  
    my ($key, $value) = split /\s*=\s*/, $val;
    $key =~ s/^\s+|\s+$//g;
    $value =~ s/^"|"$//g;
    $hash{$key}=$value;
  }
  return $hash{'filename'};
}

1;
