:input;type filter hook input priority 0

*ip;test-ip;input

tcp option eol kind 1;ok
tcp option noop kind 1;ok
tcp option maxseg kind 1;ok
tcp option maxseg length 1;ok
tcp option maxseg size 1;ok
tcp option window kind 1;ok
tcp option window length 1;ok
tcp option window count 1;ok
tcp option sack-permitted kind 1;ok
tcp option sack-permitted length 1;ok
tcp option sack kind 1;ok
tcp option sack length 1;ok
tcp option sack left 1;ok
tcp option sack0 left 1;ok;tcp option sack left 1
tcp option sack1 left 1;ok
tcp option sack2 left 1;ok
tcp option sack3 left 1;ok
tcp option sack right 1;ok
tcp option sack0 right 1;ok;tcp option sack right 1
tcp option sack1 right 1;ok
tcp option sack2 right 1;ok
tcp option sack3 right 1;ok
tcp option timestamp kind 1;ok
tcp option timestamp length 1;ok
tcp option timestamp tsval 1;ok
tcp option timestamp tsecr 1;ok

tcp option foobar;fail
tcp option foo bar;fail
tcp option eol left;fail
tcp option eol left 1;fail
tcp option eol left 1;fail
tcp option sack window;fail
tcp option sack window 1;fail
