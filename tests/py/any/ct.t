:output;type filter hook output priority 0

*ip;test-ip4;output
*ip6;test-ip6;output
*inet;test-inet;output

ct state new,established, related, untracked;ok;ct state established,related,new,untracked
ct state != related;ok
ct state {new,established, related, untracked};ok
- ct state != {new,established, related, untracked};ok
ct state invalid drop;ok
ct state established accept;ok
ct state 8;ok;ct state new
ct state xxx;fail

ct direction original;ok
ct direction != original;ok
ct direction reply;ok
ct direction != reply;ok
ct direction {reply, original};ok
- ct direction != {reply, original};ok
ct direction xxx;fail

ct status expected;ok
ct status != expected;ok
ct status seen-reply;ok
ct status != seen-reply;ok
ct status {expected, seen-reply, assured, confirmed, dying};ok
ct status expected,seen-reply,assured,confirmed,snat,dnat,dying;ok
ct status snat;ok
ct status dnat;ok
ct status xxx;fail

ct mark 0;ok;ct mark 0x00000000
ct mark or 0x23 == 0x11;ok;ct mark | 0x00000023 == 0x00000011
ct mark or 0x3 != 0x1;ok;ct mark | 0x00000003 != 0x00000001
ct mark and 0x23 == 0x11;ok;ct mark & 0x00000023 == 0x00000011
ct mark and 0x3 != 0x1;ok;ct mark & 0x00000003 != 0x00000001
ct mark xor 0x23 == 0x11;ok;ct mark 0x00000032
ct mark xor 0x3 != 0x1;ok;ct mark != 0x00000002

ct mark 0x00000032;ok
ct mark != 0x00000032;ok
ct mark 0x00000032-0x00000045;ok
ct mark != 0x00000032-0x00000045;ok
ct mark {0x32, 0x2222, 0x42de3};ok;ct mark { 0x00042de3, 0x00002222, 0x00000032}
ct mark {0x32-0x2222, 0x4444-0x42de3};ok;ct mark { 0x00000032-0x00002222, 0x00004444-0x00042de3}
- ct mark != {0x32, 0x2222, 0x42de3};ok

# ct mark != {0x32, 0x2222, 0x42de3};ok
# BUG: invalid expression type set
# nft: src/evaluate.c:975: expr_evaluate_relational: Assertion '0' failed.

ct mark set 0x11 xor 0x1331;ok;ct mark set 0x00001320
ct mark set 0x11333 and 0x11;ok;ct mark set 0x00000011
ct mark set 0x12 or 0x11;ok;ct mark set 0x00000013
ct mark set 0x11;ok;ct mark set 0x00000011
ct mark set mark;ok;ct mark set mark
ct mark set mark map { 1 : 10, 2 : 20, 3 : 30 };ok;ct mark set mark map { 0x00000003 : 0x0000001e, 0x00000002 : 0x00000014, 0x00000001 : 0x0000000a}

ct expiration 30;ok;ct expiration 30s
ct expiration 22;ok;ct expiration 22s
ct expiration != 233;ok;ct expiration != 3m53s
ct expiration 33-45;ok;ct expiration 33s-45s
ct expiration != 33-45;ok;ct expiration != 33s-45s
ct expiration {33, 55, 67, 88};ok;ct expiration { 1m7s, 33s, 55s, 1m28s}
- ct expiration != {33, 55, 67, 88};ok;ct expiration { 1m7s, 33s, 55s, 1m28s}
ct expiration {33-55};ok;ct expiration { 33s-55s}
- ct expiration != {33-55};ok

ct helper "ftp";ok
ct helper "12345678901234567";fail

ct state . ct mark { new . 0x12345678};ok
ct state . ct mark { new . 0x12345678, new . 0x34127856, established . 0x12785634};ok
ct direction . ct mark { original . 0x12345678};ok
ct state . ct mark vmap { new . 0x12345678 : drop};ok

ct original bytes \> 100000;ok;ct original bytes > 100000
ct reply packets \< 100;ok;ct reply packets < 100
ct bytes \> 100000;ok;ct bytes > 100000

# bogus direction
ct both bytes gt 1;fail
# nonsensical
ct bytes original reply;fail

# missing direction
ct saddr 1.2.3.4;fail

# direction, but must be used without
ct original mark 42;fail
# swapped key and direction
ct mark original;fail

ct label 127;ok
ct label set 127;ok
ct label 128;fail
