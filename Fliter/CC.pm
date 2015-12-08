package CC;


use Moose;

#ip=>many 
has 'RemoteIp'=>(
                 is => 'rw',
                 isa => 'Any',
                 );

###
# 根据数据库已存在的请求IP判断 判断是否 iptable
###

#查询ip是否存在
sub exists_ip{
  my $self = shift;
  my $com_ip = $self->RemoteIp->{'remoteip'};
  #selct
  
  if () {
    return 1;
  }
  
  return 0;
}

#解封IP
sub timeout{
  

}

1;
