:input;type filter hook input priority 0

*bridge;test-bridge;input

ip protocol icmp icmp type echo-request;ok;icmp type echo-request
icmp type echo-request;ok;ether type ip meta l4proto 1 icmp type echo-request
ip6 nexthdr icmpv6 icmpv6 type echo-request;ok;icmpv6 type echo-request
icmpv6 type echo-request;ok;ether type ip6 meta l4proto 58 icmpv6 type echo-request
