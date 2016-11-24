:input;type filter hook input priority 0
:ingress;type filter hook ingress device lo priority 0

*ip;test-ip4;input
*ip6;test-ip6;input
*inet;test-inet;input
*netdev;test-netdev;ingress

sctp sport 23;ok
sctp sport != 23;ok
sctp sport 23-44;ok
sctp sport != 23-44;ok
sctp sport { 23, 24, 25};ok
sctp sport != { 23, 24, 25};ok
sctp sport { 23-44};ok
sctp sport != { 23-44};ok

sctp dport 23;ok
sctp dport != 23;ok
sctp dport 23-44;ok
sctp dport != 23-44;ok
sctp dport { 23, 24, 25};ok
sctp dport != { 23, 24, 25};ok
sctp dport { 23-44};ok
sctp dport != { 23-44};ok

sctp checksum 1111;ok
sctp checksum != 11;ok
sctp checksum 21-333;ok
sctp checksum != 32-111;ok
sctp checksum { 22, 33, 44};ok
sctp checksum != { 22, 33, 44};ok
sctp checksum { 22-44};ok
sctp checksum != { 22-44};ok

sctp vtag 22;ok
sctp vtag != 233;ok
sctp vtag 33-45;ok
sctp vtag != 33-45;ok
sctp vtag {33, 55, 67, 88};ok
sctp vtag != {33, 55, 67, 88};ok
sctp vtag { 33-55};ok
sctp vtag != { 33-55};ok
