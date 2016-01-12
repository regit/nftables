:input;type filter hook input priority 0

*ip;test-ip4;input
*inet;test-inet;input
*bridge;test-bridge;input

ip saddr . ip daddr . ether saddr { 1.1.1.1 . 2.2.2.2 . ca:fe:ca:fe:ca:fe };ok
