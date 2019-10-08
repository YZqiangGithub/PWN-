from pwn import *

elf = ELF('./freenote_x86')
libc = ELF('./libc-2.19.so')
conn = remote('pwn2.jarvisoj.com','9885')



conn.interactive()