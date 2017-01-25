:input;type filter hook input priority 0

*inet;test-inet;input

ip protocol icmp icmp type echo-request;ok;icmp type echo-request
icmp type echo-request;ok
ip6 nexthdr icmpv6 icmpv6 type echo-request;ok;icmpv6 type echo-request
icmpv6 type echo-request;ok
