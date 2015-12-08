package WAF_RUN;

use lib '/home/jcc/Desktop/waf/Waf/Listen/';
use AcceptData;
use strict; 
use POSIX; 
use WAF;

sub waf_run{
  WAF::run;
}

1;
