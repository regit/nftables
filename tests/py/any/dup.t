:ingress;type filter hook ingress device lo priority 0

*netdev;test-netdev;ingress

dup to lo;ok
dup to mark map { 0x00000001 : lo, 0x00000002 : lo};ok

