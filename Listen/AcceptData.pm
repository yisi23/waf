package AcceptData;

use strict;
use warnings;
use Time::Piece::MySQL;
use Getopt::Long;
use Socket qw(IPPROTO_TCP TCP_NODELAY);
use IO::Socket::INET;
use IO::Epoll;
use Fcntl;
use POSIX qw(:errno_h);
use Thread;
#use Thread::Queue;
use Data::Dumper;
use lib '/home/jcc/Desktop/waf/Waf/Parse';
use lib '/home/jcc/Desktop/waf/Waf/Fliter';
use lib '/home/jcc/Desktop/waf/Waf/Data';
use  Data;
use FliterIP;
use ParseData;
use HTTP::Daemon;
use FliterIP;

use overload;
#http server tag
{
  no warnings;
  sub HTTP::Daemon::product_tokens
    {
    "jcb waf";
  }
}


my $sysinfolog;
my $epfd;
my $concurrent = 1000; # max event
my @Sock_Holder; #sock集合
my @dealthreads;
my $listener_fd;
my $listener;

sub init{
###
#日志监听记录
###
  $sysinfolog = new LogData();
  $sysinfolog->LogData->{'flagtype'} = "SYSTEM_LOG";
  $sysinfolog->record_open_file;
  #捕获die
  $SIG{__DIE__} = sub {
    $sysinfolog->LogData->{'systeminfo'} = $!;
    $sysinfolog->_record_log;
  };
#epoll  句柄
  $epfd = epoll_create($concurrent);

#my $request_list :shared = Thread::Queue->new();
#监听
 $listener = HTTP::Daemon->new(
                                     LocalAddr => "0.0.0.0:12345",
                                     Type      => SOCK_STREAM,
                                     Proto     => 'tcp',
                                     Blocking  => 0,#非阻塞socket
                                     Reuse     => 1,
                                     Listen    => 1024,

                                ) or  die  $!;

#记录启动那个日志
$sysinfolog->LogData->{'systeminfo'}="Waf running success";
$sysinfolog->_record_log;

print "\n";
print <<EOF;
. .-  ...   .. .
     -.++m                         .  - - - -. +-  .-+.. ---.
    .++.%-*+.- -               . .+.-+-.--+... .-+mm.m.-m.-  -
   . +%*#m-m%-- - .. -.-. ....  +- *-m--m-**%*#*##m%m*##*##-m.
   .  * ###.%+-. -   ....+.---%++m#%+%m#-.-+m +-.. +-.-++m###m.
    ... %*#%### %-+ %+.mm-*.-%+-#m#+mmmm.--m.-+ +-%-  -+m*.##m..
      + +-.+.--m*m#m#*#m*#*#**#+m-..+.. . .  . --- .   .. ++m*.m
       .+ . . -.+mm-.++  --%-%+-..+ . .  .               .+-#-
             %  +-.%+ - --m  m-    .                     ..-.+-.
             . .-+   .. .  .+   .                         -.. .
  +---------------------------------------------------------------+
  |                                                               |
  |           Waf running   \@by jcb                               |
  +---------------------------------------------------------------+

EOF
print "\n";
  $listener_fd = fileno $listener;
  epoll_ctl($epfd, EPOLL_CTL_ADD, $listener_fd, EPOLLIN) >= 0
    || die "epoll_ctl: $!\n";
  
}


sub with_sysread {
    my($ev) = @_;

    #输出连接信息
    my $sysinfo =  $Sock_Holder[$ev->[0]]->peerhost.":".$Sock_Holder[$ev->[0]]->peerport;
    print "Connect from ".$sysinfo."\n";
    #拒绝恶意IP的请求
    my $request_ip = $Sock_Holder[$ev->[0]]->peerhost;
    #cc 模块 统计IP信息
    # tiemstap ip
    my $log_time = localtime;
    my $time = $log_time->mysql_timestamp;
    my %info = (
                ip => $request_ip,
                time => $time,
               );
    my $test = new Data(
                        requestinfo => \%info,
                       );
    $test->cc;

    #调用IP过滤模块
     if (FliterIP::deny_ip($request_ip) == IpStatus::IP_Deny) {
      #丢弃数据包
       epoll_ctl($epfd, EPOLL_CTL_DEL, $ev->[0], 0) >= 0
         || die "epoll_ctl: $!\n";
       $Sock_Holder[$ev->[0]] = undef;

    }else{

      #处理数据包
      my $buf = "";

      #获取request信息
      my $r = $Sock_Holder[$ev->[0]]->get_request;


      #解析对象
      #my $ev_parse_pro = new ParseData( http_lines => \%request_data);

      #lwp
      #my $ua =new  LWP::UserAgent;

      if (defined $r){
        #print Dumper $r->as_string;
        #记录请求
        $sysinfolog->LogData->{'systeminfo'}=$Sock_Holder[$ev->[0]]->peerhost." ".$r->uri;
        $sysinfolog->LogData->{'info'}=$r->as_string;
        $sysinfolog->_record_log;
        #print Dumper $r->as_string;
        #初始化prse
        my %request_data = (
                            RequestInfo => $sysinfo,
                            RequestHeader => $r->as_string,

                           );
        my $ev_parse_pro = new ParseData( http_lines => \%request_data);
        #调用分析方法，返回HTTP::Response
        my $data = $ev_parse_pro->waf_http_parse_request_line;
        #my $data = $ua->simple_request( $r );
        $Sock_Holder[$ev->[0]]->send_response( $data );
      }else{

        # print $r->reason;
      }

      #del epoll
      if (!defined $r && ($! == EINTR || $! == EAGAIN)) {
        next;
      }

      epoll_ctl($epfd, EPOLL_CTL_DEL, $ev->[0], 0) >= 0
        || die "epoll_ctl: $!\n";
      $Sock_Holder[$ev->[0]] = undef;

    }
  }


sub _accept_socket{
  while (1) {
    my $events = epoll_wait($epfd, $concurrent, -1); # Max 1000 events returned, 1s timeout

    ### $events
    for my $ev (@$events) {
      ### ev: $ev;
      if ($ev->[0] == $listener_fd) {
        ### >listenr: $$
        my $sock = $listener->accept;
        my $sock_fd = fileno $sock;
        $Sock_Holder[$sock_fd] = $sock;

        #setsockopt($sock, IPPROTO_TCP, TCP_NODELAY, 1);
        #my $flags = fcntl($sock, F_GETFL, 0) or die "fcntl  GET_FL: $!";
        #fcntl($sock, F_SETFL, $flags|O_NONBLOCK) or die "fcntl  SET_FL: $!";

        epoll_ctl($epfd, EPOLL_CTL_ADD, $sock_fd, EPOLLIN) >= 0
          || die "epoll_ctl: $!\n";
      } else {
        ### >client: $ev->[0], $$

        &with_sysread($ev);

#        my $parse_thread_ev = threads->create(\&with_sysread,$ev);

#        push @dealthreads,$parse_thread_ev;
#        #&parse_threads_deals(@parsethreads);
#        foreach my $thr (@dealthreads) {
#            if($thr->is_running()) {
#                my $tid = $thr->tid;
#                print "  - Thread $tid running\n";
#            }
#            elsif ($thr->is_joinable()) { #释放资源
#                my $tid = $thr->tid;
#                $thr->join;
#                @dealthreads = threads->list(threads::running);
#                print "  - Results for thread $tid:\n";
#                print "  - Thread $tid has been joined\n";
#            }
#        }

      }
    }
  }
}

sub runlisten{
  &init();
  my $waf_handle_listen_data = threads->create(\&_accept_socket);
 
  #my $waf_handle_accept_data = threads->create(\&_read_request_buf);
  $waf_handle_listen_data->join();
}
1;
