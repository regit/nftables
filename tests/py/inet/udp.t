:input;type filter hook input priority 0
:ingress;type filter hook ingress device lo priority 0

*ip;test-ip4;input
*ip6;test-ip6;input
*inet;test-inet;input
*netdev;test-netdev;ingress

udp sport 80 accept;ok
udp sport != 60 accept;ok
udp sport 50-70 accept;ok
udp sport != 50-60 accept;ok
udp sport { 49, 50} drop;ok
udp sport != { 50, 60} accept;ok
udp sport { 12-40};ok
udp sport != { 13-24};ok

udp dport set {1, 2, 3};fail

udp dport 80 accept;ok
udp dport != 60 accept;ok
udp dport 70-75 accept;ok
udp dport != 50-60 accept;ok
udp dport { 49, 50} drop;ok
udp dport != { 50, 60} accept;ok
udp dport { 70-75} accept;ok
udp dport != { 50-60} accept;ok

udp length 6666;ok
udp length != 6666;ok
udp length 50-65 accept;ok
udp length != 50-65 accept;ok
udp length { 50, 65} accept;ok
udp length != { 50, 65} accept;ok
udp length { 35-50};ok
udp length != { 35-50};ok

udp checksum 6666 drop;ok
udp checksum != { 444, 555} accept;ok

udp checksum 22;ok
udp checksum != 233;ok
udp checksum 33-45;ok
udp checksum != 33-45;ok
udp checksum { 33, 55, 67, 88};ok
udp checksum != { 33, 55, 67, 88};ok
udp checksum { 33-55};ok
udp checksum != { 33-55};ok

# limit impact to lo
iif "lo" udp checksum set 0;ok
iif "lo" udp dport set 65535;ok
