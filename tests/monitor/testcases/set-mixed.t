# first the setup
I add table ip t
I add set ip t portrange { type inet_service; flags interval; }
I add set ip t ports { type inet_service; }
O -

# make sure concurrent adds work
I add element ip t portrange { 1024-65535 }
I add element ip t ports { 10 }
O -

# delete items again
I delete element ip t portrange { 1024-65535 }
I delete element ip t ports { 10 }
O -
