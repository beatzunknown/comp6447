#!/usr/bin/python3

from pwn import *

PROG_NAME = "./"
REMOTE_IP = "plsdonthaq.me"
REMOTE_PORT = 
REMOTE_LIBC = "./libc-2.23.so"
LOCAL_LIBC = "/lib32/libc.so.6"
LOCAL_LIBC = "/lib/i386-linux-gnu/libc.so.6"

if args.REMOTE:
    p = remote(REMOTE_IP, REMOTE_PORT)
    elf = ELF(PROG_NAME)
    libc = ELF(REMOTE_LIBC)
else:
    p = process(PROG_NAME)
    elf = p.elf
    libc = ELF(LOCAL_LIBC)

if args.ATTACH:
	gdb.attach(p, '''break main''')

p.interactive()