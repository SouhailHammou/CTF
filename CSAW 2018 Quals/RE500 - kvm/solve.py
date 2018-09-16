from idc import *

root = 0x1300
flag = ''

def tobits(s):
    result = []
    for c in s:
        bits = bin(ord(c))[2:]
        bits = '00000000'[len(bits):] + bits
        result.extend([[int(b) for b in bits]])
    return result


def traverse_to_leaf(element) :
	global bits
	if Byte(element) == 0xFF :
		bit = bits.pop(0)
		if element == root and bit == 1 :
			#skip
			return
		if bit == 0 :
			#left
			traverse_to_leaf(Qword(element + 8))
		else :
			#right
			traverse_to_leaf(Qword(element + 16))
	else :
		global flag
		flag += chr(Byte(element))



bl = tobits(GetManyBytes(0x580, 0x54A))
bl.reverse() #Reverse so we can start exploring from the root

#Flatten the list
bits = []
for byte in bl :
	for bit in byte :
		bits.append(bit)

while bits :
	traverse_to_leaf(root)
	
print flag[::-1] #reverse
