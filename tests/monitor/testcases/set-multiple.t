# first the setup
I add table ip t
O add table ip t
I add set ip t portrange { type inet_service; flags interval; }
O add set ip t portrange { type inet_service;flags interval }
I add set ip t portrange2 { type inet_service; flags interval; }
O add set ip t portrange2 { type inet_service;flags interval }

# make sure concurrent adds work
I add element ip t portrange { 1024-65535 }
I add element ip t portrange2 { 10-20 }
O add element ip t portrange { 1024-65535 }
O add element ip t portrange2 { 10-20 }
