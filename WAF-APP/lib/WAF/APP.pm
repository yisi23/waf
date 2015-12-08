package WAF::APP;
use Dancer ':syntax';
use lib '../lib/WAF/';
use Login;
use WAF_RUN;
#use boolean;
use Proc::Daemon;
use lib '/home/jcc/Desktop/waf/Waf/Rule/';
require RuleManage;
use Template;
use Data::Dumper;

our $VERSION = '0.1';
set session => 'YAML';

my $sa=0;
my $sess_name;
my $Kid_PID;



get '/' => sub {
     template 'login',{
	'login_url' => uri_for('/login'),
	};
};

any ['get', 'post'] => '/login' => sub {
    #获取用户输入的用户名密码
   my $username = params->{'username'};
    $sess_name = $username;
   my  $passwd = params->{'password'};
   my $login_statue = Login::sqlselect($username,$passwd);
   if($login_statue){
        #设置session
         $sa =1;
         session 'user_id' =>1;
	session user => $username;
	 redirect '/sec';
   }else{
	redirect '/';
  }
	
};

get '/sec'=> sub{
  if($sa){
    template 'sec.tt',{
                       path => $sess_name,
                       logout_url =>uri_for('/logout'),
                       dashboard_url =>uri_for('/dashboard'),
                       wafset_url => uri_for('/wafset'),
                       view_url => uri_for('/view'),
                       add_url => uri_for('/add'),
                       del_url => uri_for('/del'),  
                      };
  }else{
    redirect '/';
 }
};

get '/logout' => sub {
       session->destroy;
       #set_flash('You are logged out.');
       redirect '/';
};

#dashboard
get '/dashboard' => sub{
  if (session('user_id')) {
     use view;
     my @log = view::getlog;
     my $loo = Dumper @log;
     #return $loo;
     template 'dashboard.tt',{
                              layout => 'sec.tt',
                              path => $sess_name,
                              view_log => @log,
                              logout_url =>uri_for('/logout'),
                              dashboard_url =>uri_for('/dashboard'),
                              wafset_url => uri_for('/wafset'),
                              view_url => uri_for('/view'),
                              add_url => uri_for('/add'),
                              del_url => uri_for('/del'),  
                             };
  }else{
    redirect '/';
  }
};

any  '/wafset' => sub{
    if (session('user_id')) {
    # return params->{'wafrun'};
     template 'wafset.tt',{
                           layout => 'sec.tt',
                           path => $sess_name,
                           logout_url =>uri_for('/logout'),
                           dashboard_url =>uri_for('/dashboard'),
                           wafset_url => uri_for('/wafset'),
                           startwaf_url => uri_for('/wafrun'),
                           stopwaf_url => uri_for('/wafstop'),
                           view_url => uri_for('/view'),
                           add_url => uri_for('/add'),
                           del_url => uri_for('/del'),
                          };
  }else{
    redirect '/';
  }

};

#waf run
sub wafstart{
  my  $daemon = Proc::Daemon->new(
                                  work_dir => './',
                                  pid_del     => 'pid.txt',
                                 );
 my  $Kid_1_PID = $daemon->Init;
  unless ( $Kid_1_PID ) {
    WAF_RUN::waf_run;
    return $Kid_PID;
  }
  
}
sub wafstopp{
  #read pid waf
  open  my $FH, "pid.txt" or die $!;
  my $wafpid = <$FH>;
  system("kill -9 $wafpid");
}

  

get '/wafrun' => sub{
 # close STDIN;
 #close STDERR;

  if(session('user_id')){
   &wafstart;
    template 'wafset.tt',{
                           layout => 'sec.tt',
                           path => $sess_name,
                           logout_url =>uri_for('/logout'),
                           dashboard_url =>uri_for('/dashboard'),
                           wafset_url => uri_for('/wafset'),
                           startwaf_url => uri_for('/wafrun'),
                           stopwaf_url => uri_for('/wafstop'),
                           view_url => uri_for('/view'),
                           add_url => uri_for('/add'),
                           del_url => uri_for('/del'),
                          };
  
  }else{
    redirect '/';
  }

};
get '/wafstop' => sub{
 # close STDIN;
 #close STDERR;

  if(session('user_id')){
    &wafstopp;
    #system('kill -9 10622');
    template 'wafset.tt',{
                          layout => 'sec.tt',
                          path => $sess_name,
                          logout_url =>uri_for('/logout'),
                          dashboard_url =>uri_for('/dashboard'),
                          wafset_url => uri_for('/wafset'),
                          startwaf_url => uri_for('/wafrun'),
                          stopwaf_url => uri_for('/wafstop'),
                          view_url => uri_for('/view'),
                          add_url => uri_for('/add'),
                          del_url => uri_for('/del'),
                         };
    
  }else{
    redirect '/';
  }

};

get '/view' => sub {
  #读取规则
  my $addrule = new RuleManage;
  my @viewrule = $addrule->getallrule;
  #return  $viewrule[0][0];
  template 'rule.tt',{
                      layout => 'sec.tt',
                      allrule => \@viewrule,
                      path => $sess_name,
                      logout_url =>uri_for('/logout'),
                      dashboard_url =>uri_for('/dashboard'),
                      wafset_url => uri_for('/wafset'),
                      startwaf_url => uri_for('/wafrun'),
                      stopwaf_url => uri_for('/wafstop'),
                      view_url => uri_for('/view'),
                      add_url => uri_for('/add'),
                      del_url => uri_for('/del'),
                     };  
  
};

get '/add' =>sub{
  template 'add.tt',{
                      layout => 'sec.tt',
                      path => $sess_name,
                      logout_url =>uri_for('/logout'),
                      dashboard_url =>uri_for('/dashboard'),
                      wafset_url => uri_for('/wafset'),
                      startwaf_url => uri_for('/wafrun'),
                      stopwaf_url => uri_for('/wafstop'),
                      view_url => uri_for('/view'),
                      add_url => uri_for('/add'),
                      del_url => uri_for('/del'),
                     addrule => uri_for('/addrule'),
                     };  
  
  
};

post '/addrule' =>sub{
  #addrule
  my $tag = params->{'addruletag'};
  my $content = params->{'addrulecontent'};
  if( defined $tag &&  !($content eq "" )){
    my @adminaddrule =[
                       [$tag,$content],
                      ];
    my $laddrule = new RuleManage;
    $laddrule->addrule(\@adminaddrule);
    # redirect '/add';
    redirect '/add';
  }else{

    redirect '/add';
  }
};
get '/del' => sub{
  my $addrule = new RuleManage;
  my @viewrule = $addrule->getallrule;
  template 'del.tt',{
                     layout => 'sec.tt',
                     path => $sess_name,
                     allrule => \@viewrule,
                     logout_url =>uri_for('/logout'),
                     dashboard_url =>uri_for('/dashboard'),
                     wafset_url => uri_for('/wafset'),
                     startwaf_url => uri_for('/wafrun'),
                     stopwaf_url => uri_for('/wafstop'),
                     view_url => uri_for('/view'),
                     add_url => uri_for('/add'),
                     del_url => uri_for('/del'),
                     addrule => uri_for('/addrule'),
                     delrule=>uri_for('/delrule'),
                    };  
  
};

get '/delrule' =>sub{
  my @delrule = params->{'delrule'};
  my $addrule = new RuleManage;
  my @viewrule = $addrule->getallrule;
  
};
true;
