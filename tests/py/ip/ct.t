:output;type filter hook output priority 0

*ip;test-ip4;output

ct saddr original 192.168.0.1;ok
ct saddr reply 192.168.0.1;ok
ct daddr original 192.168.0.1;ok
ct daddr reply 192.168.0.1;ok

# same, but with a netmask
ct saddr original 192.168.1.0/24;ok
ct saddr reply 192.168.1.0/24;ok
ct daddr original 192.168.1.0/24;ok
ct daddr reply 192.168.1.0/24;ok

ct l3proto original ipv4;ok
ct l3proto reply foobar;fail

ct protocol original 6 ct proto-dst original 22;ok
ct protocol original 17 ct proto-src reply 53;ok

# wrong address family
ct daddr reply dead::beef;fail
