# first the setup
I add table ip t
I add chain ip t c
O -

I add rule ip t c accept
O -

I add rule ip t c tcp dport { 22, 80, 443 } accept
O -

I insert rule ip t c counter accept
O add rule ip t c counter packets 0 bytes 0 accept

I replace rule ip t c handle 2 accept comment "foo bar"
O delete rule ip t c handle 2
O add rule ip t c accept comment "foo bar"

I add counter ip t cnt
O add counter ip t cnt { packets 0 bytes 0 }
