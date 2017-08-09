add table ip t
add chain ip t c

# note the added handle output
add rule ip t c accept;;add rule ip t c accept # handle *
add rule ip t c tcp dport { 22, 80, 443 } accept;;add rule ip t c tcp dport { 22, 80, 443 } accept # handle *

add set ip t ipset { type ipv4_addr; }
add element ip t ipset { 192.168.0.1 }

# counter output comes with statistics
add counter ip t cnt;;add counter ip t cnt *
