# HXP CTF 2017 - revenge_of_the_zwiebel 100 pts
# Writeup link : https://rce4fun.blogspot.com/2017/11/hxp-ctf-2017-revengeofthezwiebel.html
# Souhail Hammou

from idc import *
from idaapi import *

def AddIfNotInDict(dict,index):
    if index == -1:
        raise Exception("Invalid index value !")
    if index not in dict:
        dict[index] = []

bin_dict = {}

RunTo(BeginEA())
GetDebuggerEvent(WFNE_SUSP,-1)
RunTo(0x4006A3) # CALL  ECX
GetDebuggerEvent(WFNE_SUSP,-1)


StepInto()
GetDebuggerEvent(WFNE_SUSP,-1)
block_active = 0
is_not = 0
index = -1

try :
    while True:
        #read the current instruction
        inst = GetDisasm(GetRegValue("RIP"))
        if "mov     cl, [rax+" in inst:
            block_active = 1
            try :
                index = int(inst.split("+")[1].split("]")[0].split('h')[0],16)
            except IndexError:
                index = 0
            AddIfNotInDict(bin_dict,index)
        if block_active == 1:
            if "not" in inst:
                #NOT is executed before the AND instruction
                #The bit is not set in the byte, so no need to save it
                is_not = 1
            elif "and" in inst and is_not == 0:
                #we need to save the bit that must be set
                bit = int(inst.split(",")[1].split(" ")[1].split("h")[0],16)
                #The index was set previously at the MOV CL, [RAX+X] instruction
                bin_dict[index].append(bit)
            elif "jecxz" in inst :
                #we reset our variables when we reach the JXCZ instruction
                SetRegValue(1,"RCX") #do not branch
                is_not = 0 
                block_active = 0
        StepOver() #Next instruction
        GetDebuggerEvent(WFNE_SUSP,-1)
except:
    #process terminated
    sweet_flag = ''
    for index,bits in bin_dict.iteritems():
        c = 0
        for bit in bits:
            c |= bit
        sweet_flag += chr(c)
    print "FLAG IS : " + sweet_flag
    # FLAG IS : hxp{1_5m3ll_l4zyn355}
