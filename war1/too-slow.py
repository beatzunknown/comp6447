from pwn import *

def solve(string):
	s = string.split()
	return str(int(s[0]) + int(s[2]))

#p = process('./too-slow')
p = remote('plsdonthaq.me', 1026)
p.recvline()
q = p.recv()
while not q.startswith("Well done"):
	sol = solve(q)
	p.sendline(sol)
	p.recvline()
	q = p.recv()

p.interactive()	
