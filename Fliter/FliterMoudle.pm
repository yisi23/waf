#!/usr/bin/perl -w
# FliterMoudle.pm --- 
# Author: jcc <jcc@jcb>
# Created: 12 Apr 2014
# Version: 0.01
package FliterMoudle;

use warnings;
use strict;
use lib '/home/jcc/Desktop/waf/Waf/Log';
use SQL;
use CSS;
use LogData;
use DirTraversal;
use Moose;
use AttackStatus;
use Data::Dumper;
use FileUpload;

#过滤模块整体调用class
has 'checkstr' =>(
                 is => 'rw',
                 isa => 'HashRef',
                 );

has 'requestinfo' =>(
                     is => 'rw',
                     isa => 'Str',
                    );
#log 模块
sub attack_log{
  my $attacklog= new LogData;
  $attacklog->LogData->{'flagtype'} = "ATTACK_LOG";
  $attacklog->record_open_file;
}
sub _check_attack{
  my $self = shift;
  my $fliterstr = $self->checkstr;

  
  # print 'str'.Dumper \$fliterstr;
  #log file op
  my $attacklog = $self->attacklog;
    #检测对象
 # print Dumper $self->checkstr;
  my $sqlmodle = new SQL(
                         sqlcheckstr => $self->checkstr,
                         requestinfo => $self->requestinfo,
                         attacklog => $attacklog,
                      );
  my $xssmodle = new CSS(
                         xsscheckstr => $self->checkstr,
                         requestinfo => $self->requestinfo,
                         attacklog => $attacklog,
                        );
  my $DirTraversalmodle = new DirTraversal(
                                           DirTravercheckstr => $self->checkstr,
                                           requestinfo => $self->requestinfo,
                                           attacklog => $attacklog,

                                        );
  my $FileUploadmodle;
 
 # if (   $self->checkstr ) {
    $FileUploadmodle = new FileUpload(
                                       filemessage => $self->checkstr,
                                       requestinfo => $self->requestinfo,
                                       attacklog => $attacklog,
                                     );
 # }

  #检测攻击
  my ($sqlstatus,$xssstatus,$DirTraversalstatus);
  #sql 检测
  if ($sqlmodle->_sql_injection == 0 ) {#没有攻击
    $sqlstatus = AttackStatus::NoAttack;
  }else{
    $sqlstatus = AttackStatus::Attack;
  }
  #xss检测
  if ($xssmodle->_xss_fliter == 0) {
    $xssstatus = AttackStatus::NoAttack;
  }else{
    $xssstatus = AttackStatus::Attack;
  }
  #文件遍历检测
  if ($DirTraversalmodle->_dirtrav_fliter == 0) {
    $DirTraversalstatus = AttackStatus::NoAttack;
  }else{
    $DirTraversalstatus = AttackStatus::Attack;
  }
  my $filedetectStatus;
  #文件上传检测
  if (defined $FileUploadmodle) {
      $filedetectStatus = $FileUploadmodle->_file_fliter; 
      $attacklog->close_log_file;
  }

  #返回检测结果
  if (($xssstatus == AttackStatus::Attack) || ($sqlstatus == AttackStatus::Attack) || ($DirTraversalstatus == AttackStatus::Attack)
      || $filedetectStatus == AttackStatus::Attack ) {
    #存在攻击
    print "attack";
    return AttackStatus::Attack;
  }else{
    #没有检测到攻击
    print "no attack";
    return AttackStatus::NoAttack;
  }
}

#Log
sub attacklog{
  my $attackinfolog = new LogData();
  $attackinfolog->LogData->{'flagtype'} = "ATTACK_LOG";
  $attackinfolog->record_open_file;
  return $attackinfolog;
}

1;
__END__

=head1 NAME

FliterMoudle.pl - Describe the usage of script briefly

=head1 SYNOPSIS

FliterMoudle.pl [options] args

      -opt --long      Option description

=head1 DESCRIPTION

Stub documentation for FliterMoudle.pl, 

=head1 AUTHOR

jcc, E<lt>jcc@jcbE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2014 by jcc

This program is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.2 or,
at your option, any later version of Perl 5 you may have available.

=head1 BUGS

None reported... yet.

=cut
