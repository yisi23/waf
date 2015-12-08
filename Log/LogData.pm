package LogData;
##
#记录原始数据及转发数据、攻击数据
##
use Moose;
use Switch;
use Time::Piece;
use IO::File;
use Time::Piece::MySQL;
#use Carp;
#log格式

#log file 路径
use constant {
  SYSLOG => '/home/jcc/Desktop/waf/Waf/Log/sys.log',
    LISTENLOG => '/home/jcc/Desktop/waf/Waf/Log/listen.log',
    ATTACKLOG => '/home/jcc/Desktop/waf/Waf/Log/attack.log',
    FORWARDLOG => '/home/jcc/Desktop/waf/Waf/Log/forward.log',
    OTHERLOG => '/home/jcc/Desktop/waf/Waf/Log/other.log',
};

has 'LogData' =>(
                 is => 'rw',
                 isa => 'HashRef',
                 default => sub {{}},
                );

# 记录
sub _record_log{
  my $self = shift;
  my $record_log = $self->get_log_info();
  $self->record_write_file($record_log);
}

#记录other log
  sub other_log{
    my $self = shift;
    $self->LogData->{'filetype'} = 'OTHER';
    my $other_file = $self->record_open_file();
    my $record_log = $self->get_log_info();
    $self->record_write_file($other_file);
  }
  
#获取系统时间
sub get_record_time{
  my $log_time = localtime;
  return $log_time->mysql_datetime;
  
}

#文件句柄操作
sub record_open_file{
  my $self  = shift;
  my $flagtype  = $self->LogData->{'flagtype'};
  my $file_flag;
  switch ($flagtype) {
    
    case "SYSTEM_LOG"   { $file_flag = SYSLOG }
      case "LISTEN_LOG"    { $file_flag =LISTENLOG }
      case "ATTACK_LOG"    { $file_flag = ATTACKLOG }
      case "FORWARD_LOG" { $file_flag = FORWARDLOG }
      else		 { $file_flag = OTHERLOG }
  }
  #打开文文件句柄
  my $fh = new IO::File ">> $file_flag";
  if (not defined $fh) {
    print "log file operate error";
  }else{
    $self->LogData->{'fh'} = $fh; 
    return $fh;
  }
}

#写入文件
sub record_write_file{
  my $self = shift;
  my $record_string = shift;
  syswrite( $self->LogData->{'fh'},$record_string,length($record_string));
}

#获取log 信息
sub get_log_info{
  my $self = shift;
  #syslog info2
  my $flagtype = $self->LogData->{'flagtype'};
  my $time = $self->get_record_time;
  switch ($flagtype) {
    
    case "SYSTEM_LOG"   {
                         return $time." ".$self->LogData->{'systeminfo'}."\n";
                        }
      case "LISTEN_LOG" {
                         return $time." ".$self->LogData->{'listenlog'}."\n";
                        }
      case "ATTACK_LOG" {
                         return $time." ".$self->LogData->{'attacklog'}."\n";
                        }
      case "FORWARD_LOG"{
                         return $time." ".$self->LogData->{'forwardlog'}."\n";
                        }
      else {
        return $time.$flagtype."can't record the log";
           }
  }

}

#关闭 file io
sub close_log_file{
  my $self = shift;
  my $fh = $self->LogData->{'fh'};
  $fh->close;
}
#test

#my $test = new LogData;
#$test->LogData->{'flagtype'} = "SYSTEM_LOG";
#$test->LogData->{'systeminfo'} = "run";
#$test->_record_log;
#$test->close_log_file;
1;
