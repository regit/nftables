:output;type filter hook input priority 0

*ip;test-ip4;output
*ip6;test-ip6;output
*inet;test-inet;output

rt classid "cosmos";ok
