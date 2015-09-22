*ip;test-ip4
*ip6;test-ip6
*inet;test-inet
*arp;test-arp
*bridge;test-bridge
:output;type filter hook output priority 0

limit rate 400/minute;ok
limit rate 20/second;ok
limit rate 400/hour;ok
limit rate 40/day;ok
limit rate 400/week;ok
limit rate 1023/second burst 10 packets;ok

limit rate 1 kbytes/second;ok
limit rate 2 kbytes/second;ok
limit rate 1025 kbytes/second;ok
limit rate 1023 mbytes/second;ok
limit rate 10230 mbytes/second;ok
limit rate 1023000 mbytes/second;ok

limit rate 1025 bytes/second burst 512 bytes;ok
limit rate 1025 kbytes/second burst 1023 kbytes;ok
limit rate 1025 mbytes/second burst 1025 kbytes;ok
limit rate 1025000 mbytes/second burst 1023 mbytes;ok
