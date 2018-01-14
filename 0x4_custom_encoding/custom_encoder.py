#!/usr/bin/env python


from __future__ import print_function
import argparse
import random

import pdb

DEBUG=False


# for assembly check custom_decoder.nasm
custom_decoder_stub = "\xeb\x22\x5e\x89\xf7\x8a\x17\x46\x31\xc9\x31\xdb\x88\xd1\x8a\x1e\x46\x30\x1e\x28\x16\x8a\x06\x88\x07\x47\x46\xe2\xf4\xf6\x06\xff\x74\x07\xeb\xe4\xe8\xd9\xff\xff\xff"

def gen_parser():
    parser = argparse.ArgumentParser(description='helper script for SLAE')
    parser.add_argument("-b","--badchars", help="list of badchars that need to be avoided in encoded")
    parser.add_argument("-o","--opcode", help="return opcodes from elf binary")
    parser.add_argument("-ec","--encodecustom", help="shellcode to encode and key to encode with", nargs="+")
    parser.add_argument("-dc","--decodecustom", help="shellcode to decode ")
    parser.add_argument("-r","--reverse", help="reverse ascii string and output in stack push commands")
    parser.add_argument("--debug", help="turn on debugging mode",action="store_true") 
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




def custom_encode(shellcode,rot_key):
    '''
    Custom encoder that uses a divisible number as the rot shift and encodes the resulting text with xor key.
    Pads the shellcode to make it divisible by the rot cypher key 
    Adds the decoder stub from custom_decoder.nasm to output
    '''
    rot_key=int(rot_key)
    shellcode=bytearray(shellcode.decode('string_escape'))
    sclen=len(shellcode)
    print("\n\n Shellcode length :\t%i\n" % sclen)

    if(sclen % rot_key == 0):
            print("\n\n!!!ROT KEY WILL BE %i!!!\n\n" % rot_key)
    else:
        # pad it with 0x00 until it's divisible by rot_key
        # null bytes are chosen because they will be xored and will make sure the shellcode is terminated when decoded
        counter=0
        print("\n\nPadding with x00 codes to even out the bytes...\n" )
        #print("len(%i)\trot_key(%i)" % (sclen,rot_key))
        while not (int(sclen+counter) % rot_key == 0):
            counter+=1
            shellcode.append('\x00')

        if(DEBUG):
            print("=" * 20)
            print("\n\n!!!Added %i NOP codes as padding for ROT cypher %i!!!!\n\n" % (counter,rot_key))
            print("=" * 20)

        sclen+=counter

    # random byte to xor every x bytes where x = rot_key 
        if(DEBUG):
            print("=" * 20)
            print("\n\nAdding random byte every %i bytes to use as XOR key\n\n" % (rot_key))
            print("=" * 20)
    step=0
    modArr=bytearray()
    modArr+=bytearray(custom_decoder_stub)
    modArr.append(chr(rot_key))
    # randomize xor byte, leave 0xFF for marker
    #xor_key=random.randint(0,255)
    #modArr.append(chr(xor_key))

    for x in range(0,(sclen/rot_key)):
        #print("Adding byte from [%i:%i]" % (step,step+rot_key))

        #randomize xor byte, leave 255 for marker
        xor_key=random.randint(0,254)

        if(DEBUG):
            print("=" * 20)
            print('Using %s to xor encode the next %i bytes' % (hex(xor_key),rot_key))
            print("=" * 20)

        modArr.append(chr(xor_key))
        for b in shellcode[step:step+rot_key]:
            # rot cypher
            b+=rot_key
            if b > 256:
                #print("rolling over %i" % b)
                # roll over
                b=b-256
            # xor with previous byte
            xb=b^int(hex(xor_key),16)
            modArr.append(xb)
        step+=rot_key
        
    # add the last x bytes where x is rot_key
    for lb in shellcode[step::]:
        # rot cypher
        lb+=rot_key
        if lb > 256:
            #print("rolling over %i" % lb)
            # roll over
            lb=lb-256
        xlb=lb^int(hex(xor_key),16)
        modArr.append(xlb)

        # Now add the 0xFF marker so the decode knows when to call it
    modArr.append(chr(255))

    return modArr

def custom_decode(shellcode):
    '''
    decoder to test the custom encoding
    Take first byte to know how to reverse ROT cypher
    - XOR decode the next x bytes with the key prepended
    - reverse the ROT

    '''
  
    shellcode=bytearray(shellcode.decode('string_escape'))
    decodedArr=bytearray()

    rot_key=shellcode[0]
    xor_key=shellcode[1]

    print("ROT KEY:\t%i\t\t XOR_KEY:\t%i\n" % (rot_key,xor_key))
    print("=" * 20)
    # drop the byte
    shellcode=shellcode[1::]
    #jump in groups of x ( where x is rot_key ) to decrypt bytes
    step=0
    print("Doing %i iterations\n\n" % (len(shellcode)/rot_key))
    for x in range(0,len(shellcode)/rot_key):
        # check for marker
        if(hex(xor_key)=="0xff"):
            print("\n Marker found %s, stopping decode routine!!!\n" % hex(xor_key))
            break
        print("\n Iteration %i with XOR KEY %s\n" % (x,hex(xor_key)))
        for b in shellcode[step+1:step+1+rot_key]:
            # xor decrypt and reverse ROT cypher
            print("Parsing byte %s"% hex(b))
            xb=b^xor_key
            xb-=rot_key
            #print(xb)
            if xb < 0:
                # roll over
                xb=xb+256
            decodedArr.append(xb)
        step+=(rot_key+1)
        xor_key=shellcode[step]

    return decodedArr


if __name__ == '__main__':
    # get all the arguments in
    parser=gen_parser() 
    args=parser.parse_args()
    if args.debug:
        print("[+] Debugging activated")
        DEBUG=True
    if args.opcode:
        print("Generating opcodes from elf binary...")
        print("=" * 20)
        get_opcodes(args.opcode)

    if args.reverse:
        reverse_string(args.reverse)
    
    if args.encodecustom:
        counter=1
        if(args.badchars):
                rArr=custom_encode(args.encodecustom[0],args.encodecustom[1])
                # give up after 10 so no infinite loop
                while(check_for_badchars(args.badchars,rArr) and counter!=10):
                    rArr=custom_encode(args.encodecustom[0],args.encodecustom[1])
                    print("\n[+] Bad chars are in resulting payload, trying again\n")
                    counter+=1 

                if counter==10:
                    print("\n[!] Giving up generating payload after %i iterations...\n" % counter)
                    print("[!] Badchars coulnd't be avoided in %i iterations\n\n" % counter)
                else:
                    pp_ba_hex(rArr)
                    pp_ba_or(rArr)
                    print("\n[+] Finished generating payload using %i iterations\n\n" % counter)
        else:
            rArr=custom_encode(args.encodecustom[0],args.encodecustom[1])
            pp_ba_hex(rArr)
            pp_ba_or(rArr)
            print("\n[+] Finished generating payload using %i iterations\n\n" % counter)

    if args.decodecustom:
        rArr=custom_decode(args.decodecustom)
        pp_ba_hex(rArr)
        pp_ba_or(rArr)


