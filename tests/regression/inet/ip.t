*ip;test-ip4
*inet;test-inet
*bridge;test-bridge

:input;type filter hook input priority 0

ip saddr . ip daddr . ether saddr { 1.1.1.1 . 2.2.2.2 . ca:fe:ca:fe:ca:fe };ok
