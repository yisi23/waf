package ParseStatus;
#定义解析完成的状态
use strict;
use constant {
  W_Incomplete => -2,
    W_Broken => -1,
    W_Get => 1,
    W_Post => 2,
    W_Other_M => 0,
};


1;
