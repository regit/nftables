:prerouting;type filter hook prerouting priority 0

*ip;test-ip;prerouting
*ip6;test-ip6;prerouting

fib saddr . daddr oif lo;fail
fib iif . oif . daddr oif lo;fail
fib mark oif lo;fail
fib saddr . iif oif ne 0;ok;fib saddr . iif oif != 0
fib saddr . iif oifname "lo";ok

fib daddr . iif type local;ok
fib daddr . iif type vmap { blackhole : drop, prohibit : drop, unicast : accept };ok
fib daddr . oif type local;fail

fib daddr oif exists;ok
fib daddr oif missing;ok
