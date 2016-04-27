:input;type filter hook input priority 0
:ingress;type filter hook ingress device lo priority 0

*ip6;test-ip6;input
*inet;test-inet;input
*netdev;test-netdev;ingress

!w type ipv6_addr;ok
!x type inet_proto;ok
!y type inet_service;ok
!z type time;ok

?set2 192.168.3.4;fail
!set2 type ipv6_addr;ok
?set2 1234:1234::1234:1234:1234:1234:1234;ok
?set2 1234:1234::1234:1234:1234:1234:1234;fail
?set2 1234::1234:1234:1234;ok
?set2 1234:1234:1234:1234:1234::1234:1234 1234:1234::123;ok
?set2 192.168.3.8 192.168.3.9;fail
?set2 1234:1234::1234:1234:1234:1234;ok
?set2 1234:1234::1234:1234:1234:1234;fail
?set2 1234:1234:1234::1234;ok

ip6 saddr @set2 drop;ok
ip6 saddr @set33 drop;fail
