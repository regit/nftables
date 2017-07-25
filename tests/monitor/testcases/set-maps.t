# first the setup
I add table ip t
I add map ip t portip { type inet_service: ipv4_addr; flags interval; }
O -

I add element ip t portip { 80-100: 10.0.0.1 }
O -

I add element ip t portip { 1024-65535: 10.0.0.1 }
O -
