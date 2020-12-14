#!/usr/bin/python3

from pwn import *

PROG_NAME = "./"
REMOTE_IP = "plsdonthaq.me"
REMOTE_PORT = 

if args.REMOTE:
    p = remote(REMOTE_IP, REMOTE_PORT)
    elf = ELF(PROG_NAME)
else:
    p = process(PROG_NAME)
    elf = p.elf

if args.ATTACH:
	gdb.attach(p, '''break main''')

p.interactive()