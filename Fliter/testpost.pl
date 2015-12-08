#!/usr/bin/perl

my $str =  "__VIEWSTATE=%2FwEPDwUJMTk5OTI1MTIzZGRIlMIVgK9qwddaKLqFe%2B0HKFeCbwuwgzIA8Y1RnEJZCg%3D%3D&__EVENTVALIDATION=%2FwEWBAL0%2FP2sDgLs0bLrBgLs0fbZDAKM54rGBlbw6O1weWgHXe5kPqHwlhlvAlzbYa3WesaNWc7x2j2v&TextBox1=%27+or+1%3D1%3B--&TextBox2=%27+or+1%3D1%3B--&Button1=%E7%99%BB%E5%BD%95%E7%B3%BB%E7%BB%9F";

if ($str =~ /%27\+or\+1%3D1%3B--/ix) {
  print 1;
}else{
  print 0;
}
