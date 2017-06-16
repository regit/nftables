:input;type filter hook input priority 0
:ingress;type filter hook ingress device lo priority 0

*inet;test-inet;input

meta nfproto ipv4;ok
meta nfproto ipv6;ok
meta nfproto {ipv4, ipv6};ok
meta nfproto != {ipv4, ipv6};ok

