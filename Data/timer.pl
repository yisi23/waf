#!/usr/bin/perl

use AnyEvent;
use threads;
use IO::File;


    my $parse_thread_ev = threads->create(sub{
                                            my $cv = AnyEvent->condvar;
                                            my $five_seconds = AnyEvent->timer(after => 1, cb => sub {
                                                                                 $cv->send;
                                                                                 my $fh = new IO::File ">> data";
                                                                                 my $str = " wlecome \n";
                                                                                 syswrite( $fh,$str,length($str));
                                                                               });
                                            $cv->recv;
                                          });

    my @dealthreads;
    push @dealthreads,$parse_thread_ev;
    foreach my $thr (@dealthreads) {
      if($thr->is_running()) {
        my $tid = $thr->tid;
        print "  - Thread $tid running\n";
      }
      elsif ($thr->is_joinable()) { #释放资源
        my $tid = $thr->tid;
        $thr->join;
        @dealthreads = threads->list(threads::running);
                print "  - Results for thread $tid:\n";
        print "  - Thread $tid has been joined\n";
      }
    }
 
