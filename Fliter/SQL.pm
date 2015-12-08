#!/usr/bin/perl
#检测SQL攻击
#!/usr/bin/perl
#检测SQL攻击
package SQL;

#use Strict;
use Moose;
use Data::Dumper;
#(X_FORWARD_FOR  User_agent 分析用户) Cookie GET POST  (Referer 记录来源)
#https://github.com/nbs-system/naxsi/blob/master/naxsi_config/naxsi_core.rules
#http://www.symantec.com/connect/articles/detection-sql-injection-and-cross-site-scripting-attacks
#定义需要检测的http request
#sql 关键字select|union|update|delete|insert|table|from|ascii|hex|unhex|drop
#perl meta-character \ ^ $ . | ( ) [ ] * + ?  ||  . $ ^ { [ ( | ) * + ?\
# -- sqlserver oracle postgres db2 ingres; # mysql 
has 'SqlRuleFlag' =>(
                     is =>'ro',
                     isa =>'ArrayRef',
                     default => sub{[0,1]},#0不存在g此攻击 1攻击报警
                    );
has 'SqlRule' =>(
                 is => 'rw',
                 isa => 'ArrayRef',
                 default =>sub{ [
                                 #qr/(%27)|(\')|(--)|(%23)|(\#)/,#检测单引号，注释 -- #//ix
                                 #qr/(%2F%2A)|(\/\*)|(%2A%2F)|(\*\/)/,# /* */  注释  //ix eg '/**/UN/**/ION/**/SEL/**/ECT/**/password/**/FR/**/OM/**/tblUsers/**/WHE/**/RE/**/username/**/LIKE/**/'admin'--
                                # qr/((%3D)|(=))[^\\n]*((%27)|(\')|(--)|(%3B)|(;))/,#检测 = ' -- ; //i
                                 qr/\w*((%27)|(\'))\w*((%6F)|o|(%4F))((%72)|r|(%52))\w*/, #检测1'or'1'='1. //ix
                                 qr/((%27)|(\'))union/,#union //ix ' or 1=1;--
                                 qr/exec(\s|\+)+(s|x)p\w+/,#ms-sql //ix
                                 qr/select|union|update|delete|insert|table|from|ascii|hex|unhex|drop/,#keywords
                                 qr/\w*((%27)|(\'))\w*(and|or)/,#and 1=1;
                                 qr/(%00)/,#%00
                                 qr/char\((\w+|\d+|.)\)/,#char() 编码
                                 qr/(\'(\w+)\'\+\'(\w+)\')|(\'(\w+)\'\|\|\'(\w+)\')|(concat\((\w+),(\w+)\))|(concat\((\'\w+\'),(\'\w+\')\))|(("(\w+)")&("(\w+)"))/,#字符串拼接
                                 qr/substring\((\w+|\d+)\)/,#substring
                                 #qr/((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/,
                                 qr/%27\+or\+1%3D1%3B--/,
                                 qr/((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/,#1'or'1'='1
                                 qr/((\%27)|(\'))union/,
                                ]},
               
                );
has 'sqlcheckstr' => (
                  is => 'rw',
                  isa => 'HashRef',
                );
has 'requestinfo'=>(
                    is => 'rw',
                    isa =>'Str',
                   );
has 'attacklog' =>(
                   is => 'rw',
                   isa => 'Any',
                  );
#检测是否匹配
sub _sql_injection{
  my $self = shift;
  my $sql_find_str = $self->sqlcheckstr;
  #print Dumper $sql_find_str;
  my @sql_detect;
  if (exists $sql_find_str->{'filename'}){
     @sql_detect = qw/ uri UserAgent cookie/;
  }else{
     @sql_detect = qw/ uri UserAgent cookie content/;
  }
  
  for my $x ( @{ $self->SqlRule } ) {
    for my $key (@sql_detect){
       my $value =  $self->sqlcheckstr->{$key};
    
       #print $value."\n";
       if ( defined($value)){
         if( $value =~ /$x/ix){
           #log模块
           print  " $value -->match rules: $x\n";
           $self->attacklog->LogData->{'attacklog'}="SQL ".$self->requestinfo." Rule:".$x;
           $self->attacklog->_record_log;
           return ${ $self->SqlRuleFlag }[1];
         }
       }
     }
  }
  return ${ $self->SqlRuleFlag }[0];
}
#添加新的规则
sub _add_rule{
  my $self = shift;
  my $new_rule = shift;
  unshift( @{$self->SqlRule},$new_rule);
}
#test

#my $str =  "__VIEWSTATE=%2FwEPDwUJMTk5OTI1MTIzZGRIlMIVgK9qwddaKLqFe%2B0HKFeCbwuwgzIA8Y1RnEJZCg%3D%3D&__EVENTVALIDATION=%2FwEWBAL0%2FP2sDgLs0bLrBgLs0fbZDAKM54rGBlbw6O1weWgHXe5kPqHwlhlvAlzbYa3WesaNWc7x2j2v&TextBox1=%27+or+1%3D1%3B--&TextBox2=%27+or+1%3D1%3B--&Button1=%E7%99%BB%E5%BD%95%E7%B3%BB%E7%BB%9F";
#my $reg_testcheckstr = \%str;
#my $reg_test = new SQL();
#$reg_test->_sql_injection($str);
1;

