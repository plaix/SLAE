; Filename: test_execve.nasm
; Author:  Plaix ; Website:  http://slacklabs.be ;
; Purpose: 

; Compile:
; --------
;
; nasm -f elf32 -o $execve.o $execve.nasm
; ld -o $execve $execve.o




global _start			

section .text

_start:
	;int execve(const char *filename, char *const argv[], char *const e    nvp[]);
	; execve ("/bin/sh", ["/bin/sh", "-i"], 0);
	xor edx, edx
	push edx
	
	; //usr/bin/python
	; String length : 16
	push 0x6e6f6874	; noht
	push 0x79702f6e	; yp/n
	push 0x69622f72	; ib/r
	push 0x73752f2f	; su//

	; //bin/sh
	;push 0x68732f6e
	;push 0x69622f2f

	mov ebx, esp
	; param -i
	;push edx
	;push word 0x692d
	;mov ecx, esp

	push edx
	;push ecx
	push ebx
	mov ecx, esp
	mov byte al,0xb
	int 0x80
