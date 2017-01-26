:output;type filter hook output priority 0
:ingress;type filter hook ingress device lo priority 0

*ip;test-ip4;output
*ip6;test-ip6;output
*inet;test-inet;output
*arp;test-arp;output
*bridge;test-bridge;output
*netdev;test-netdev;ingress

%cnt1 type counter;ok
%qt1 type quota 25 mbytes;ok
%qt2 type quota over 1 kbytes;ok
