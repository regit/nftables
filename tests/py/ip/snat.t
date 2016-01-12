:postrouting;type nat hook postrouting priority 0

*ip;test-ip4;postrouting

iifname "eth0" tcp dport 80-90 snat 192.168.3.2;ok
iifname "eth0" tcp dport != 80-90 snat 192.168.3.2;ok
iifname "eth0" tcp dport {80, 90, 23} snat 192.168.3.2;ok
- iifname "eth0" tcp dport != {80, 90, 23} snat 192.168.3.2;ok
- iifname "eth0" tcp dport != {80, 90, 23} snat 192.168.3.2;ok
# BUG: invalid expression type set
# nft: src/evaluate.c:975: expr_evaluate_relational: Assertion '0' failed.

iifname "eth0" tcp dport != 23-34 snat 192.168.3.2;ok
