# ip_mutation
This is a elementary step to defend scanning-based attacks.

exp-topo2 is used to create topo.

ip_mutation_mine5 is used to configure pox controller.

use "python exp-topo2.py" to create topo with 10 switches and 10 hosts.

use "python pox.py ip_mutation_mine5" to configure the controller.

ip_mutation_mine5_end2 is new added. We add DNS sever to code in order to change first_dstip into vip.
