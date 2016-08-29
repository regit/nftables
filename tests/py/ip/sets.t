:input;type filter hook input priority 0
:ingress;type filter hook ingress device lo priority 0

*ip;test-ip4;input
*inet;test-inet;input
*netdev;test-netdev;ingress

!w type ipv4_addr;ok
!x type inet_proto;ok
!y type inet_service;ok
!z type time;ok

!set1 type ipv4_addr;ok
?set1 192.168.3.4;ok

?set1 192.168.3.4;ok
?set1 192.168.3.5 192.168.3.6;ok
?set1 192.168.3.5 192.168.3.6;ok
?set1 192.168.3.8 192.168.3.9;ok
?set1 192.168.3.10 192.168.3.11;ok
?set1 1234:1234:1234:1234:1234:1234:1234:1234;fail
?set2 192.168.3.4;fail

!set2 type ipv4_addr;ok
?set2 192.168.3.4;ok
?set2 192.168.3.5 192.168.3.6;ok
?set2 192.168.3.5 192.168.3.6;ok
?set2 192.168.3.8 192.168.3.9;ok
?set2 192.168.3.10 192.168.3.11;ok

ip saddr @set1 drop;ok
ip saddr @set2 drop;ok
ip saddr @set33 drop;fail

!set3 type ipv4_addr flags interval;ok
?set3 192.168.0.0/16;ok
?set3 172.16.0.0/12;ok
?set3 10.0.0.0/8;ok

!set4 type ipv4_addr flags interval;ok
?set4 192.168.1.0/24;ok
?set4 192.168.0.0/24;ok
?set4 192.168.2.0/24;ok
?set4 192.168.1.1;fail
?set4 192.168.3.0/24;ok
