:input;type filter hook input priority 0
:ingress;type filter hook ingress device lo priority 0

*bridge;test-bridge;input
*netdev;test-netdev;ingress

vlan id 4094;ok
vlan id 0;ok
# bad vlan id
vlan id 4096;fail
vlan id 4094 vlan cfi 0;ok
vlan id 4094 vlan cfi != 1;ok
vlan id 4094 vlan cfi 1;ok
# bad cfi
vlan id 4094 vlan cfi 2;fail
vlan id 4094 vlan cfi 1 vlan pcp 8;fail
vlan id 4094 vlan cfi 1 vlan pcp 7;ok
vlan id 4094 vlan cfi 1 vlan pcp 3;ok

ether type vlan vlan id 4094;ok;vlan id 4094
ether type vlan vlan id 0;ok;vlan id 0
ether type vlan vlan id 4094 vlan cfi 0;ok;vlan id 4094 vlan cfi 0
ether type vlan vlan id 4094 vlan cfi 1;ok;vlan id 4094 vlan cfi 1
ether type vlan vlan id 4094 vlan cfi 2;fail

vlan id 4094 tcp dport 22;ok
vlan id 1 ip saddr 10.0.0.1;ok
vlan id 1 ip saddr 10.0.0.0/23;ok
vlan id 1 ip saddr 10.0.0.0/23 udp dport 53;ok
ether type vlan vlan id 1 ip saddr 10.0.0.0/23 udp dport 53;ok;vlan id 1 ip saddr 10.0.0.0/23 udp dport 53

vlan id { 1, 2, 4, 100, 4095 } vlan pcp 1-3;ok
vlan id { 1, 2, 4, 100, 4096 };fail

# illegal dependencies
ether type ip vlan id 1;fail
ether type ip vlan id 1 ip saddr 10.0.0.1;fail
