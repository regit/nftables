:input;type filter hook input priority 0

*ip;test-ip;input

flow table xyz { ip saddr timeout 30s counter packets 0 bytes 0};ok
