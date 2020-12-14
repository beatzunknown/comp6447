#!/usr/bin/python3

# A simple binary enumeration script

import sys
from pwn import *

if len(sys.argv) < 2:
	exit()

PROG_NAME = sys.argv[1]
LOCAL_LIBC = "/lib32/libc.so.6"
LOCAL_LIBC = "/lib/i386-linux-gnu/libc.so.6"

p = process(PROG_NAME)
elf = p.elf
libc = ELF(LOCAL_LIBC)

elf.checksec()
HAS_WIN = 'win' in elf.symbols
print("Has win:", HAS_WIN)
HAS_SYSTEM = 'system' in elf.plt
print("Has system:", HAS_SYSTEM)
HAS_EXECVE = 'execve' in elf.plt
print("Has execve:", HAS_EXECVE)

p.interactive()

p.sendline(cyclic(0x1000))
p.wait()
core = Coredump('./core')
print("bof offset:", cyclic_find(core.eip))

