:input;type filter hook input priority 0
:ingress;type filter hook ingress device lo priority 0

*inet;test-inet;input

meta nfproto ipv4 ct original saddr 1.2.3.4;ok
meta nfproto ipv6 ct original saddr ::1;ok

# missing protocol context
ct original saddr ::1;fail
