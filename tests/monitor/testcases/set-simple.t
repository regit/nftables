# first the setup
I add table ip t
I add set ip t portrange { type inet_service; flags interval; }
O -

# adding some ranges
I add element ip t portrange { 1-10 }
O -
I add element ip t portrange { 1024-65535 }
O -
I add element ip t portrange { 20-30, 40-50 }
O add element ip t portrange { 20-30 }
O add element ip t portrange { 40-50 }

# test flushing -> elements are removed in reverse
I flush set ip t portrange
O delete element ip t portrange { 1024-65535 }
O delete element ip t portrange { 40-50 }
O delete element ip t portrange { 20-30 }
O delete element ip t portrange { 1-10 }

# make sure lower scope boundary works
I add element ip t portrange { 0-10 }
O -

# make sure half open before other element works
I add element ip t portrange { 1024-65535 }
I add element ip t portrange { 100-200 }
O -

# make sure deletion of elements works
I delete element ip t portrange { 0-10 }
O -
I delete element ip t portrange { 100-200 }
I delete element ip t portrange { 1024-65535 }
O -

# make sure mixed add/delete works
I add element ip t portrange { 10-20 }
I add element ip t portrange { 1024-65535 }
I delete element ip t portrange { 10-20 }
O -
