package Data;


use DBI;
use Moose;

has 'sql' => (
              is => 'rw',
              isa => 'Str',
             );


sub connectdbi{
  #数据库信息
  my $source = "DBI:mysql:oa:database=waf;host=localhost;";
  my $username = "root";
  my $password = "1";
  
  my $dbc = DBI->connect($source, $username, $password)
  or die "Unable to connect to mysql: $DBI::errstr\n";
  return $dbc;
}

sub sqlselect{
  my $self = shift;
  my $dbc = connectdbi;
  my $query_sql = $self->Str;
  my $sql = $dbc->prepare($query_sql);  

  my $out = $sql->execute()
    or die "Unable to execute sql: $sql->errstr";
  
#  while (($id) = $sql->fetchrow_array())
 #   {
 #     print "Id: $id\n";
 #   }
}
1;

#test     ip  time  frequency
my $sql = "selct * from requestinfo";
my $test = new Data(
                   'sql' = $sql,
                  );

  my $log_time = localtime;
  print $log_time->mysql_time;
