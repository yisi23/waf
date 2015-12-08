package FileUpload;

#检测文件类型及文件内容那个是否含有恶意代码


#detect mime-type filesize
# 文件上传
#http://www.ietf.org/rfc/rfc1867.txt
# multipart/form-data
#http://www.ietf.org/rfc/rfc2388.txt
#
use Moose;
use MIME::Types;
use AttackStatus;
use lib '../Log';
use LogData;
use SQL;
use CSS;
use Data::Dumper;

extends 'SQL';
extends 'CSS';
#一个HTTP::Message Object
#$mess->content_charset 
has 'filemessage' =>(
                      is => 'rw',
                      isa => 'Any',
                     );
has 'requestinfo' =>(
                     is => 'rw',
                     isa => 'Str',
                    );
has 'attacklog' =>(
                   is => 'rw',
                   isa => 'Any',
                  );
has 'fiename_w' =>(
                   is => 'rw',
                   isa => 'Any',
                   default => 0,
                  );
has 'filecontent_w' =>(
                       is => 'rw',
                       isa => 'Any',
                       default => 0,
                      );
#恶意代码特征库 PATTERNS="passthru|shell_exec|system|phpinfo|base64_decode|popen|exec|proc_open|pcntl_exec|python_eval|fopen|fclose|readfile"
#<? eval($_GET['cmd']); ?>
#
#  <? system($_GET['cmd']); ?>
#<? preg_replace('/.*/e',$_POST['code']); ?>
has 'phpmalicouscode'=>(
                        is => 'rw',
                        isa => 'HashRef',
                        default => sub {
                          {
                            shell_exec  => 10,
                              system    => 10,
                              phpinfo   => 10,
                              base64_decode =>10,
                              popen     =>10,
                              exec      =>10,
                              proc_open =>10,
                              pcntl_exec =>10,
                              python_eval =>10,
                              fopen =>10,
                              fclose =>10,
                              readfile =>10,
                              preg_replace =>10,
                              eval =>10,
                          }
                        },
                       );

#mime type detect
sub get_content_type{
  my $self = shift;
  my $mimetypes = MIME::Types->new;
  my   $content_type = $self->filemessage->{'filetype'};
  my MIME::Type $plaintext = $mimetypes->type($content_type);
  print $plaintext->mediaType;   # text
  print $plaintext->subType;     # plain
  # 
  
}
#filetype
sub detect_filetype{
  &get_content_type;
  
}

#file name detect (dirtravel xss)
sub detectfilename{
  my $self = shift;
  #不允许的文件上传
  my $filename_w = 0;
  if (defined $self->filemessage->{'filename'}){
    my @filetype = split (/\./, $self->filemessage->{'filename'});
   
    my @filetype_black =qw/php php3 php4 phtml pl py jsp asp htm shtml sh cgi/;
    my $filename_detect = pop @filetype;
 
    if (defined $filename_detect){
      for my $ev (@filetype_black){
        if ($ev eq $filename_detect ){
          $self->attacklog->LogData->{'attacklog'} = "filetype ".$self->requestinfo." Rule:".$ev;
          $self->attacklog->_record_log;
          
          return  $filename_w = 10;
        }
      }
      return $filename_w;
    }
  }
  return $filename_w;
}
#file content detect (evel code)
sub detectfilecontent{
  my $self = shift;
  my $filecontent_w = 0;
  
  
  my $filecontent = $self->filemessage->{'filecontent'};
  #print Dumper $filecontent;
  if ( defined $filecontent ){
    foreach  my $key (keys %{ $self->phpmalicouscode }) {
          # print $key;
      #my $value=  $self->phpmalicouscode->{$key};
      if ( $filecontent =~ $key ){
   
        $self->attacklog->LogData->{'attacklog'} = "Malicouse ".$self->requestinfo." Rule:".$key;
        $self->attacklog->_record_log;
        $filecontent_w += 10;
      }
    }
    return $filecontent_w;
  }else{
    return $filecontent_w;
  }
}

#detect
sub _file_fliter{
  my $self = shift;
 
  my $dect1 = $self->detectfilename;
  my $dect2 = $self->detectfilecontent;

  if ( $dect1 > 0 && ($dect1+$dect2) >= 20){
    return AttackStatus::Attack;
  }else{
    return AttackStatus::NoAttack;
  }
}


1;
