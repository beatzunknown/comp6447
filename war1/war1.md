intro
===========================
Flag: FLAG{}
General overview of problems faced
-------------------------------------
- Exploit working on local binary but not remote, due to EOFErrors: `recv()` wouldn't complete before my `sendline()` ran so there was non deterministic behaviour with my script. I was able to identify this as the issue after Adam mentioned the `DEBUG` flag for running my python script. The solution was to not use `recv()` but instead `recvline()` and `recvuntil()` since this would definitively read data until a certain character was reached.
- Providing the requested flag: initially I had ran `strings` and then piped it to `grep` to find "FLAG{" but there was nothing. I eventually found "password" which looked out of place so I tried it and it worked.
- Not getting the actual flag: there was no indicator that there was more for me to do once I had received the "you have completed the basics" message. I only realised I had to enter interactive mode after completing `too-slow` where the final message was "enjoy your shell". I had actually seen "bin/sh" when I used `strings` on the binary but I guess I didn't put 2 and 2 together at the time.
- Runtime errors: I ran into a lot of these which were pretty much due to me not using the pwntools functions correctly. Things like not casting ints to strings before using them with `sendline()`. As I developed more familiarity with pwntools and looked up the documentation, things started to work more smoothly

Script/Command used
------------------
There's not much to the code this week. Essentially I just read in the text from the program, extract the numbers and data i'm interested in, do the required processing/conversion and send data back to the program.
```
from pwn import *

#p = process('./intro')
p = remote('plsdonthaq.me', 1025)
p.recvuntil('{')
num = p.recvuntil('}', drop=True)
num_dec = int(num, 16)
p.sendline(str(num_dec))
p.recvuntil('MINUS ')
new_hex = hex(num_dec - int(p.recvuntil('!', drop=True), 16))
p.sendline(new_hex)
p.recvlines(3)
little_endian = p32(num_dec)
p.sendline(little_endian)
little_endian_to_int = u32(p.recvlines(3)[-1])
little_endian_to_hex = hex(little_endian_to_int)
p.recvline()
p.sendline(str(little_endian_to_int))
p.recvlines(3)
p.sendline(little_endian_to_hex)
sum_problem = p.recvlines(2)[-1][:-1].split()
sum_sol = int(sum_problem[-3]) + int(sum_problem[-1])
p.sendline(str(sum_sol))
p.recvlines(3)
p.sendline('password')
print(p.recv())
p.interactive()
```
too-slow
=============
Flag: FLAG{}
General overview of problems faced
-------------------------------------
 - Time-constraint: since the program would close very quickly, I wasn't really able to play around with the program manually so I had to dive straight into scripting an exploit.

In terms of actually making my exploit, I didn't really have any issues. After gaining familiarity with the pwntool commands in the `intro` exercise, I found this one to be pretty straightforward. The only "catch" I encountered would probably be that I had to use `recv()` instead of `recvline()` to get the sum problem because it didn't end with a newline character.

Script/Command used
------------------
The script I made just repeatedly reads in data from the program, solves the given calculation question and sends the response back. This repeats until we get the "well done" success message and we get a shell. We can interact with the shell once pwntools enters interactive mode.
```
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
```