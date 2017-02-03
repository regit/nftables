:prerouting;type nat hook prerouting priority 0

*ip;test-ip4;prerouting

iifname "eth0" tcp dport 80-90 dnat to 192.168.3.2;ok
iifname "eth0" tcp dport != 80-90 dnat to 192.168.3.2;ok
iifname "eth0" tcp dport {80, 90, 23} dnat to 192.168.3.2;ok
iifname "eth0" tcp dport != {80, 90, 23} dnat to 192.168.3.2;ok
iifname "eth0" tcp dport != 23-34 dnat to 192.168.3.2;ok
iifname "eth0" tcp dport 81 dnat to 192.168.3.2:8080;ok

dnat to ct mark map { 0x00000014 : 1.2.3.4};ok
dnat to ct mark . ip daddr map { 0x00000014 . 1.1.1.1 : 1.2.3.4};ok
