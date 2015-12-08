package Data;


use DBI;
use Moose;
use Time::Piece::MySQL;
use AnyEvent;
use Data::Dumper;
use threads;
use threads::shared;

use constant CC_TIMES => 30;

has 'requestinfo' => (
              is => 'rw',
              isa => 'Any',
             );

#数据库信息
my $source = "DBI:mysql:oa:database=waf;host=localhost;";
my $username = "root";
my $password = "19910230";

sub sqlconnect{
  return DBI->connect($source, $username, $password)
      or die "Unable to connect to mysql: $DBI::errstr\n";
}
sub sqlselect{
  my $ip = shift;
  my $flag = shift;
  my $query_sql = "select * from requestinfo where ip=?";
  my $sql;
  my $dbc = &sqlconnect;
  $sql = $dbc->prepare($query_sql);
  $sql->execute("$ip")
    or die "Unable to execute sql: $sql->errstr";
  my $ipinfo =$sql->fetchrow_hashref;
  return $ipinfo;
}
sub cc{
  my $self = shift;
  
  my $ipinfo = sqlselect($self->requestinfo->{'ip'});
  
  if ($ipinfo) {#包含此IP比较查看次数是否大于2分钟
    #第一次请求时的时间
    my $request_ip :shared = $self->requestinfo->{'ip'};
    my $frequency = $ipinfo->{'frequency'};
    #
    if ($frequency ==  1) {
      #启动定时器
      print "second request\n";
      my $timer_thread = threads->create(sub{
                                  my $cv = AnyEvent->condvar;
                                  my $ipinfo = $request_ip;
                                  my $five_seconds = AnyEvent->timer(after => 10, cb => sub {
                                                                       print "timer start \n";
                                                                       $cv->send;
                                                                       #查询当前请求次数
                                                                       my $currentinfo = &sqlselect($ipinfo);
                                                                       my $current_times = $currentinfo->{'frequency'};
                                                                       print Dumper "requeset info:".$currentinfo."\n";
                                                                       my $ip = $currentinfo->{'ip'};
                                                                       my $del_ip = &sqlconnect;
                                                                       
                                                                       #判断当前次数是否大于规定的次数
                                                                       if ( $current_times >= CC_TIMES ){
                                                                         print "根据规则阻止IP\n";
                                                                         #大于我们规定的次数，因此利用iptables阻止掉5分钟
                                                                         system("iptables -A INPUT  -s $ip -j DROP");
                                                                         my $drop_rule = "iptables -D INPUT -s $ip -j DROP";
                                                                         system("at now +5 minutes <<END
$drop_rule 
<<END
");
                                                                         #加入规则删除数据库的ip信息
                                                                         print "del ip from database";
                                                                         my $sqldelip ="delete from requestinfo where ip=?";
                                                                         my $ipdel = $del_ip->prepare($sqldelip);
                                                                         $ipdel->execute($request_ip);
                                                                         $ipdel->finish();
                                                                       }else{
                                                                         #不是攻击源，删除数据库中的数据
                                                                         my $sqldelip ="delete from requestinfo where ip=?";
                                                                         my $ipdel = $del_ip->prepare($sqldelip);
                                                                         $ipdel->execute($request_ip);
                                                                         $ipdel->finish();
                                                                       }
                                                                       
                                                                       
                                                                     });
                                  $cv->recv;
                                });
      
      my @dealthreads;
      push @dealthreads,$timer_thread;
      foreach my $thr (@dealthreads) {
        if($thr->is_running()) {
          my $tid = $thr->tid;
          print "  - Thread $tid running\n";
        } elsif ($thr->is_joinable()) { #释放资源
          my $tid = $thr->tid;
          $thr->join;
          @dealthreads = threads->list(threads::running);
          print "  - Results for thread $tid:\n";
          print "  - Thread $tid has been joined\n";
        }
      }
       my $dbh = &sqlconnect;
      my $sth = $dbh->prepare("UPDATE requestinfo
SET    frequency  = 2 
WHERE ip =?");
      $sth->execute($request_ip) or die $DBI::errstr;
      #print "Number of rows updated :" + $sth->rows;
      $sth->finish();
    }else{#更新请求次数
      print "update request times\n";
      my $dbh = &sqlconnect;
      my $sth = $dbh->prepare("UPDATE requestinfo
SET    frequency  = frequency + 1 
WHERE ip =?");
      $sth->execute($request_ip) or die $DBI::errstr;
      print "Number of rows updated :" + $sth->rows;
      $sth->finish();
    }
    
    #print $frequency."\n";
    #print $self->requestinfo->{'time'};
    
  }else{#不包含IP初次请求 写入IP信息及timestamp
    print "--------firest request----------- \n";
    my $ip = $self->requestinfo->{'ip'};
    my $add_request_info =  "INSERT INTO requestinfo (ip,time,frequency) VALUES(?,?,?)";
    my $dbc = &sqlconnect;
    my $insertsql=$dbc->prepare($add_request_info);
    my $time = $self->requestinfo->{'time'};
    $insertsql->execute("$ip","$time",1);
  }
}

1;

#test     ip  time  frequency

#my $log_time = localtime;
#my $time = $log_time->mysql_timestamp;
#my %info = (
#            ip => "1.1.1.44",
#            time => $time,
#           );
#my $test = new Data(
#                    requestinfo => \%info,
#                   );
#$test->cc;


#while(1){}
#<<EOF
####事件定时器 每一次第一次请求出发定时器 到两分钟时 清空
