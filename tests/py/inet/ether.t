*ip;test-ip4
*ip6;test-ip6
*inet;test-inet
*bridge;test-bridge

:input;type filter hook input priority 0

tcp dport 22 iiftype ether ether saddr 00:0f:54:0c:11:4 meta nfproto ipv4 accept;ok;tcp dport 22 ether saddr 00:0f:54:0c:11:04 meta nfproto ipv4 accept
tcp dport 22 iiftype ether ether saddr 00:0f:54:0c:11:4 accept;ok;tcp dport 22 ether saddr 00:0f:54:0c:11:04 accept
tcp dport 22 ether saddr 00:0f:54:0c:11:04 accept;ok

ether saddr 00:0f:54:0c:11:04 accept;ok
ether saddr 00:0f:54:0c:11:04 meta nfproto ipv4;ok
