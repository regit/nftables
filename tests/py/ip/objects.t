:output;type filter hook output priority 0

*ip;test-ip4;output

%cnt1 type counter;ok
%cnt2 type counter;ok
%qt1 type quota 25 mbytes;ok
%qt2 type quota over 1 kbytes;ok

ip saddr 192.168.1.3 counter name "cnt2";ok
ip saddr 192.168.1.3 counter name "cnt3";fail
counter name tcp dport map {443 : "cnt1", 80 : "cnt2", 22 : "cnt1"};ok
ip saddr 192.168.1.3 quota name "qt1";ok
ip saddr 192.168.1.3 quota name "qt3";fail
quota name tcp dport map {443 : "qt1", 80 : "qt2", 22 : "qt1"};ok
