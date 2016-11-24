:postrouting;type nat hook postrouting priority 0

*ip;test-ip4;postrouting

iifname "eth0" tcp dport 80-90 snat to 192.168.3.2;ok
iifname "eth0" tcp dport != 80-90 snat to 192.168.3.2;ok
iifname "eth0" tcp dport {80, 90, 23} snat to 192.168.3.2;ok
iifname "eth0" tcp dport != {80, 90, 23} snat to 192.168.3.2;ok

iifname "eth0" tcp dport != 23-34 snat to 192.168.3.2;ok
