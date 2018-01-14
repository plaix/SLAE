#!/usr/bin/env python

from __future__ import print_function

from capstone import *
from keystone import *
import argparse
import subprocess
import random

# Only supports Linux x86 atm
PLATFORM=CS_MODE_32
ARC=CS_ARCH_X86

KS_PLATFORM=KS_MODE_32
KS_ARC=KS_ARCH_X86

# memory address where emulation starts
ADDRESS = 0x1000000

# will contain the unused registers after map_code is executed
REGISTERS={"eax":["ax","ah","al"],"ebx":["bx","bh","bl"],"ecx":["cx","ch","cl"],"edx":["dx","dh","dl"],"esi":['si'],"edi":['di']}

# filler instructions we can use to pad the shellcode
INSTRUCTIONS=["cld","std"]
# index to all the syscalls
SYSCALLLIST=[0]

DEBUG=False

def asm_command(ks,instructions):
    #print("[+] Assembling command %s" % instructions)
    mnemonic=instructions.split(' ')[0]
    op_str=' '.join(instructions.split(' ')[1::])
  
    # print the new command
    if(DEBUG):
        print("\x1b[6;30;42m\t%s\t%s\x1b[0m" %( mnemonic, op_str))
    # calculate the opcodes
    opcodes,count=ks.asm(instructions)
    
    return opcodes

# disassemble code using capstone before running it
def c_dis(code):
    md = Cs(ARC, PLATFORM)
    for (address, size, mnemonic, op_str) in md.disasm_lite(code, ADDRESS):
            if (mnemonic == "int" and op_str == "0x80"):
                print("\x1b[7;30;42m0x%x:\t%s\t%s\x1b[0m" %(address, mnemonic, op_str))
            else:
                print("0x%x:\t%s\t%s" %(address, mnemonic, op_str))

def poly_group(code):
    '''

    - if we see a push value
    - Check to see if we have unused registers to play with
    - Add 1 to value to push and mov it into unused register
    - subtract 1 from said register 
    - set esp manualy
    - inject filler instructions if requested
    - Use the predefined alternate instructions to alter code at random

    '''
    
    codeBuf=bytearray()
    # dis
    md = Cs(ARC, PLATFORM)
    # asm
    ks = Ks(KS_ARC, KS_PLATFORM)


    for (address, size, mnemonic, op_str) in md.disasm_lite(code, ADDRESS):
            # don't always obfuscate push commands to keep size down
            pushObfus=bool(random.getrandbits(1))

            if (mnemonic == "int" and op_str == "0x80"):
                if(DEBUG):
                    print("\x1b[7;30;42m\t%s\t%s\x1b[0m" %(mnemonic, op_str))
                for x in bytearray(code[int(address-ADDRESS):int(address-ADDRESS)+size]):
                    codeBuf.append(x)

            elif (mnemonic == "push" and "eax" in op_str ):
                if(pushObfus):
                    if(DEBUG):
                        print(";\t%s\t%s" %( mnemonic, op_str))
                    codeBuf.extend(asm_command(ks,"mov [esp-4],eax"))
                    codeBuf.extend(asm_command(ks,"sub esp,0x04"))
            elif (mnemonic == "push" and "ebx" in op_str ):
                if(pushObfus):
                    if(DEBUG):
                        print(";\t%s\t%s" %( mnemonic, op_str))
                    codeBuf.extend(asm_command(ks,"mov [esp-4],ebx"))
                    codeBuf.extend(asm_command(ks,"sub esp,0x04"))
            elif (mnemonic == "push" and "ecx" in op_str ):
                if(pushObfus):
                    if(DEBUG):
                        print(";\t%s\t%s" %( mnemonic, op_str))
                    codeBuf.extend(asm_command(ks,"mov [esp-4],ecx"))
                    codeBuf.extend(asm_command(ks,"sub esp,0x04"))
            elif (mnemonic == "push" and "edx" in op_str ):
                if(pushObfus):
                    if(DEBUG):
                        print(";\t%s\t%s" %( mnemonic, op_str))
                    codeBuf.extend(asm_command(ks,"mov [esp-4],edx"))
                    codeBuf.extend(asm_command(ks,"sub esp,0x04"))
            elif (mnemonic == "push" and "0x" in op_str ):
                if(pushObfus):
                    # substract by 1
                    # make it into a mov
                    # check to see if we have registers in the whitelist
                    if(len(REGISTERS)!=0):
                        if(DEBUG):
                            print(";\t%s\t%s\x1b" %( mnemonic, op_str))
                        #print("size:%i\tinstruction:%s" % (size,op_str))
                        # if we're not dealing with a word push
                        if(size != 4):
                            op_str="0x"+''.join(["%02x" % (x+1) for x in bytearray(code[int(address-ADDRESS)+1:int(address-ADDRESS)+size][::-1])])
                                # adjust the bytes in the codeBuf
                            codeBuf.extend(asm_command(ks,"mov %s,%s" %( REGISTERS.keys()[0],op_str)))
                            op_str="0x"
                            for x in range(len(bytearray(code[int(address-ADDRESS)+1:int(address-ADDRESS)+size]))):
                                    op_str+='01'
                            codeBuf.extend(asm_command(ks,"sub %s,%s" %( REGISTERS.keys()[0],op_str)))
                            op_str=REGISTERS.keys()[0]
                            codeBuf.extend(asm_command(ks,"push %s" %( REGISTERS.keys()[0])))
                        else:
                            # word push, shift 2 bytes due to the opcode for word
                            op_str="0x"+''.join(["%02x" % (x+1) for x in bytearray(code[int(address-ADDRESS)+2:int(address-ADDRESS)+size][::-1])])
                            codeBuf.extend(asm_command(ks,"mov %s,%s" %( REGISTERS.keys()[0],op_str)))
                            op_str="0x"
                            for x in range(len(bytearray(code[int(address-ADDRESS)+2:int(address-ADDRESS)+size]))):
                                    op_str+='01'
                            codeBuf.extend(asm_command(ks,"sub %s,%s" %( REGISTERS.keys()[0],op_str)))

                            op_str=REGISTERS.keys()[0]
                            # push a word so use the word size regs first value of the REGISTERS dict items
                            codeBuf.extend(asm_command(ks,"push %s" %( REGISTERS.values()[0][0])))
                else:
                    if(DEBUG):
                        print("\t%s\t%s" %( mnemonic, op_str))
                    for x in bytearray(code[int(address-ADDRESS):int(address-ADDRESS)+size]):
                        #print("appending \\x%02x to codeBuffer" % x )
                        codeBuf.append(x)
            else:
                if(DEBUG):
                    print("\t%s\t%s" %( mnemonic, op_str))
                # add to codeBuf
                for x in bytearray(code[int(address-ADDRESS):int(address-ADDRESS)+size]):
                    #print("appending \\x%02x to codeBuffer" % x )
                    codeBuf.append(x)
    return codeBuf

def map_code(code):
    '''
    Check which registers are used
    Check which instructions we can use as filler 
    Split the shellcode up into groups based on syscalls
    return the resulting groups so randomization can be done on selected or all groups
    '''
    #code=b"\x31\xc0\x31\xd2\x50\x66\x68\x2d"
    md = Cs(ARC, PLATFORM)
    for (address, size, mnemonic, op_str) in md.disasm_lite(code, ADDRESS):
            # Check if a register is used and update the whitelist
            for k,v in REGISTERS.items():
                if(k in op_str):
                    del REGISTERS[k]
                else:
                    #check for other representations of the register
                    for x in v:
                        if(x in op_str):
                            del REGISTERS[k]
            # Check to see which instructions we can use as filler
            for x in INSTRUCTIONS:
                if(x in op_str):
                     INSTRUCTIONS.remove(x)

            # get the syscalls locations
            if (mnemonic == "int" and op_str == "0x80"):
                SYSCALLLIST.append(int(address-ADDRESS))

    print("Unused registers %s" % REGISTERS.keys())
    print("Whitelisted filler instructions %s" % INSTRUCTIONS)
    print("Syscall locations %s" % SYSCALLLIST[1:])

def modify_code(code):
    '''

    Ask for each group if polymorphism needs to be applied
    if not just append the normal code to the modified buffer

    '''

    y=0
    modifiedCode=bytearray()
    for x in range(len(SYSCALLLIST)-1):
        #pp_ba_hex(bytearray(code[syscallList[x]+y:syscallList[x+1]+2]))
        #print("working through code from %s - %s" % ((syscallList[x]+y),(syscallList[x+1]+2)))
        print("[+] Group %i" % x)
        print("-" * 10)
        c_dis(code[SYSCALLLIST[x]+y:SYSCALLLIST[x+1]+2])
        print("-" * 10)
        choice=raw_input("Run through poly routine?(y/n):")
        if('y' in choice):
            print("[+] Running group %i through poly routine" % x)
            modifiedCode.extend(poly_group(code[SYSCALLLIST[x]+y:SYSCALLLIST[x+1]+2]))
        else:
            print("[+] skipping group %i" % x)
            modifiedCode.extend(code[SYSCALLLIST[x]+y:SYSCALLLIST[x+1]+2])

        y=2
    
    incSize=round(((len(modifiedCode)-len(code))/float(len(code)))*100,0)
    print("Original shellcode length: %i\nModified shellcode length: %i\nIncreased by %i percent" % (len(code),len(modifiedCode),incSize))
    bResult=check_for_badchars("\\x00",modifiedCode)
    if(bResult):
        print("[+] null bytes detected !!")
    pp_ba_hex(modifiedCode)
    pp_ba_or(modifiedCode)


def gen_parser():
    parser = argparse.ArgumentParser(description='helper script for SLAE')
    parser.add_argument("-d","--disassemble", help="disassemble shellcode using capstone")
    parser.add_argument("-b","--badchars", help="list of badchars that need to be avoided in encoded")
    parser.add_argument("-o","--opcode", help="return opcodes from elf binary")
    parser.add_argument("-r","--reverse", help="reverse ascii string and output in stack push commands")
    parser.add_argument("--debug", help="turn on debugging mode",action="store_true")
    parser.add_argument("-s","--spy", help="hook known syscalls while emulating",action="store_true")
    return parser

def reverse_string(sInput):
    print ('String length : ' +str(len(sInput)))

    stringList = [sInput[i:i+4] for i in range(0, len(sInput), 4)]

    for item in stringList[::-1] :
            #print (item[::-1] + ' : ' + str(item[::-1].encode('hex')))
            print ("push 0x" + str(item[::-1].encode('hex')) + '\t; ' + item[::-1])

def get_opcodes(elfLoc):
    """Helper functions to Get opcode from ELF binary / uses objdump """
    p = subprocess.Popen(['objdump','-d','-M','intel',elfLoc],stdout=subprocess.PIPE,
                                                      stderr=subprocess.PIPE)
    out,errr = p.communicate()
    #print(out)
    #print("=" * 20)
    print("creating opcode lines...")
    opcodes=out.split('\n')
    opcodes=filter(None,opcodes)
    obuf=[]

    for t in opcodes[3::]:
        #print("DEBUG: results....")
        #print(t)
        if len(t.split('\t')) >= 2: # dirty hack for labels FIXME
            #print(t.split('\t')[1])
            for i in filter(None,t.split('\t')[1].split(" ")):
        #        print(i)
                # check for null bytes
                if i == 0:
                    print("Null byte detected!!")
                    print("\n\n"+t+"\n\n")
                    pass
                obuf.append(int(i,16))
        #obuf+="\\x"+(t.split('\t')[1].strip()).replace(" ","\\x")

    pp_ba_hex(bytearray(obuf))
    pp_ba_or(bytearray(obuf))

    pass

def pp_ba_hex(bArr):
    #print(bArr)
    print("Printing hex output with len %i" % len(bArr))
    print("=" * 20)

    print("".join([str("\\x"+"%02x" % x) for x in bArr]))

def pp_ba_or(bArr):
    #print(bArr)
    print("Printing or output with len %i" % len(bArr))
    print("=" * 20)
    
    print(",".join([str("0x"+"%02x" % x) for x in bArr]))


def check_for_badchars(bclist,shellcode):
    '''
    returns false if badchars are found in resulting shellcode
    '''
    bclist=bytearray(bclist.decode('string_escape'))

    #print (''.join('\\x{:02x}'.format(x) for x in bytearray(shellcode)))
    #print ("\n\n")
    #print (''.join('\\x{:02x}'.format(x) for x in bytearray(bclist)))
    for x in bytearray(bclist):
        result=bytearray(shellcode).find(bytearray(chr(x)))
        if result != -1:
            #print("\n[+] Bad char found, retrying encoding ...")
            #print(hex(shellcode[result]))
            return True

    # We're golden
    return False

if __name__ == '__main__':
    # get all the arguments in
    parser=gen_parser() 
    args=parser.parse_args()
    if args.debug:
        DEBUG=True
    if args.opcode:
        print("Generating opcodes from elf binary...")
        print("=" * 20)
        get_opcodes(args.opcode)

    if args.disassemble:
        print("\nMapping shellcode...")
        print("=" * 20)
        # argparse escapes the \ so we need to decode it before we disassemble it
        map_code(args.disassemble.decode('string_escape'))
        print("%i syscall groups identified" % (len(SYSCALLLIST)-1))
        modify_code(args.disassemble.decode('string_escape'))
        #c_dis(args.disassemble, CS_ARCH_X86, CS_MODE_32)
    #    test_i386(UC_MODE_32, X86_CODE32_SELF)
        print("=" * 20)
    if args.reverse:
        reverse_string(args.reverse)
