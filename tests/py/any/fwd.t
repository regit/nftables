:ingress;type filter hook ingress device lo priority 0

*netdev;test-netdev;ingress

fwd to lo;ok
fwd to mark map { 0x00000001 : lo, 0x00000002 : lo};ok

