*ip;test-ip4
:prerouting;type nat hook prerouting priority 0

iifname "eth0" tcp dport 80-90 dnat 192.168.3.2;ok
iifname "eth0" tcp dport != 80-90 dnat 192.168.3.2;ok
iifname "eth0" tcp dport {80, 90, 23} dnat 192.168.3.2;ok
- iifname "eth0" tcp dport != {80, 90, 23} dnat 192.168.3.2;ok
- iifname "eth0" tcp dport != {80, 90, 23} dnat 192.168.3.2;ok
# BUG: invalid expression type set
# nft: src/evaluate.c:975: expr_evaluate_relational: Assertion '0' failed.

iifname "eth0" tcp dport != 23-34 dnat 192.168.3.2;ok

dnat ct mark map { 0x00000014 : 1.2.3.4};ok
dnat ct mark . ip daddr map { 0x00000014 . 1.1.1.1 : 1.2.3.4};ok
