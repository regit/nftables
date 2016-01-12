# filter chains available are: input, output, forward
:input;type filter hook input priority 0
:forward;type filter hook forward priority 0
:output;type filter hook output priority 0

*arp;test-arp;input,forward,output
