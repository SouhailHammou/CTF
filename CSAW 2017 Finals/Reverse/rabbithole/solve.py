#Souhail Hammou - 2017
#Run the script in IDA

from idaapi import *
from idc import *

def traverse_find(node,c):
	if get_byte(node) == 1:
		r = get_byte(node+8) & 0x1
		if r == 1:
			return 1
		else:
			return 0
	b1 = get_byte(node+8)
	b2 = get_byte(node+9)
	if c >= b1 and c < b2:
		return traverse_find(get_qword(node+0x10),c)
	else:
		return traverse_find(get_qword(node+0x18),c)

flag = ''
roots = 0x000000000028F900; # The array of nodes start at this address

for i in range(0,0x3b) :
	node = get_qword(roots) #read the node's address
	c = 0x20
	while c <= 0x7f : #our charset
		if traverse_find(node,c) == 1:
			flag += chr(c) #right char
			break
		c += 1
	roots += 8 #next root node

print flag

# flag{b3g1n_47_7h3_b3g1nn1ng_4nd_g0_0n_t1ll_y0u_h1t_th3_3nd}
