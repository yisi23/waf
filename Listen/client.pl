#!/usr/bin/perl -w
# Filename : client.pl
use IO::Socket::INET;
 
# auto-flush on socket
$| = 1;
 

 
# data to send to a server
   my $sendinfo='GET http://www.baidu.com/id=select HTTP/1.1
Host: www.baidu.com
Proxy-Connection: keep-alive
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Encoding: gzip,deflate,sdch
Accept-Language: en-US,en;q=0.8,zh-CN;q=0.6,zh;q=0.4
Accept-Charset: UTF-8,*;q=0.5
Cookie: BAIDU_WISE_UID=wapspace_1346089211_217; BDUT=ikytABF1EFF4FD4DE2D7791C8C37F4EAE6FD13c3d148d620; locale=zh; pgv_pvi=4017060864; bdshare_firstime=1382965918963; Hm_lvt_9f14aaa038bbba8b12ec2a4a3e51d254=1382963971,1383573981; BAIDUID=8DE3E20D7CBD5D433CA81AEE228DB7F5:FG=1; Hm_lvt_f4165db5a1ac36eadcfa02a10a6bd243=1394371164; BDUSS=VZZnVwMFM5cVB4VlFVbU9CVXFaaExPRWxvcmhTeUgtZGh-dzAzRkF4Wno0Rk5UQVFBQUFBJCQAAAAAAAAAAAEAAABZgSw4amNjX25vAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHNTLFNzUyxTeW; MCITY=-%3A; cflag=65535:1; H_PS_PSSID=4684_5230_1439_6154_6056_4760_6018_5856_6099

';
for(my $i=0;$i<300;$i++){
# create a connecting socket
my $socket = new IO::Socket::INET (
    PeerHost => '127.0.0.1',
    PeerPort => '12345',
    Proto => 'tcp',
);
die "cannot connect to the server $!\n" unless $socket;
print "connected to the server\n";
my $size = $socket->send($sendinfo);
print "sent data of length $size\n";
 
# notify server that request has been sent
shutdown($socket, 1);
 
# receive a response of up to 1024 characters from server
my $response = "";
$socket->recv($response, 1024);
print "received response: $response\n";
 
$socket->close();
    }
