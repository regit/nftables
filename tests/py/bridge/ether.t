:input;type filter hook input priority 0

*bridge;test-bridge;input

tcp dport 22 iiftype ether ip daddr 1.2.3.4 ether saddr 00:0f:54:0c:11:4 accept;ok;tcp dport 22 ether saddr 00:0f:54:0c:11:04 ip daddr 1.2.3.4 accept
tcp dport 22 ip daddr 1.2.3.4 ether saddr 00:0f:54:0c:11:04;ok;tcp dport 22 ether saddr 00:0f:54:0c:11:04 ip daddr 1.2.3.4
tcp dport 22 ether saddr 00:0f:54:0c:11:04 ip daddr 1.2.3.4;ok
ether saddr 00:0f:54:0c:11:04 ip daddr 1.2.3.4 accept;ok

ether daddr 00:01:02:03:04:05 ether saddr set ff:ff:ff:ff:ff:ff drop;ok
