:output;type filter hook output priority 0

*ip;test-ip4;output

ct original saddr 192.168.0.1;ok
ct reply saddr 192.168.0.1;ok
ct original daddr 192.168.0.1;ok
ct reply daddr 192.168.0.1;ok

# same, but with a netmask
ct original saddr 192.168.1.0/24;ok
ct reply saddr 192.168.1.0/24;ok
ct original daddr 192.168.1.0/24;ok
ct reply daddr 192.168.1.0/24;ok

ct original l3proto ipv4;ok
ct reply l3proto foobar;fail

ct original protocol 6 ct original proto-dst 22;ok
ct original protocol 17 ct reply proto-src 53;ok

# wrong address family
ct reply daddr dead::beef;fail
