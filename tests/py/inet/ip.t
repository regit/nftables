:input;type filter hook input priority 0
:ingress;type filter hook ingress device lo priority 0

*ip;test-ip4;input
*inet;test-inet;input
*bridge;test-bridge;input
*netdev;test-netdev;ingress

ip saddr . ip daddr . ether saddr { 1.1.1.1 . 2.2.2.2 . ca:fe:ca:fe:ca:fe };ok
