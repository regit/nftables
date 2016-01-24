:input;type filter hook input priority 0
:ingress;type filter hook ingress device lo priority 0

*ip;test-ip4;input
*inet;test-inet;input
*netdev;test-netdev;ingress

mark set ip saddr map { 10.2.3.2 : 0x0000002a, 10.2.3.1 : 0x00000017};ok;mark set ip saddr map { 10.2.3.1 : 0x00000017, 10.2.3.2 : 0x0000002a}
