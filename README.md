Work files for the SLAE cert on http://www.securitytube.net/video/6707
Mostly linux x86 shellcode and helper scripts

Compile tips
-

for the compiled file
 gcc -fno-stack-protector -z execstack shellcode.c -o shellcode

To get the opcodes from compiled nasm file


bjdump -d ./PROGRAM|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
