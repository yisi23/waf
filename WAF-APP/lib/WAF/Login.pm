package Login;
use DBI;
use Crypt::SaltedHash;
#数据库信息
my $source = "DBI:mysql:oa:database=waf;host=localhost;";
my $data_username = "root";
my $data_password = "1";


  
sub connect_login{
  return DBI->connect($source, $data_username, $data_password)
      or die "Unable to connect to mysql: $DBI::errstr\n";
}
sub sqlselect{
  my $username = shift;
  my $passwd = shift;
  my $query_sql = "select * from login where username=?";
  my $sql;
  my $dbc = &connect_login;
  $sql = $dbc->prepare($query_sql);
  $sql->execute("$username")
    or die "Unable to execute sql: $sql->errstr";
  my $userinfo =$sql->fetchrow_hashref;
  if ($userinfo) {
    #exists
    my $currentpasswd = $userinfo->{'passwd'};
   chomp $currentpasswd;
    chomp $passwd;
    #print $currentpasswd;
    if (Crypt::SaltedHash->validate($currentpasswd, $passwd)) {
      return 1;
    }else{
      #passwd error
      return 0;
    }
  }else{
    #not exists
    return 0;

  }
}
1;
