from pwn import *


'''
highlevel:
'''


p = process('./runner')

#p.recvuntil('enter your shellcode:')

'''
1. Print "hello world\n" to stdout:

the string in ascii backwards is: 0a 64 6c 72 6f 77 20 6f 6c 6c 65 68
we split this into chunks of 4 bytes: 0x0a646c72 0x6f77206f 0x6c6c6568 \x00
'''
shellcode1 = asm("""xor eax, eax
					push eax
					push 0x0a646c72
					push 0x6f77206f
					push 0x6c6c6568

					mov al, 0x4
					mov ebx, 0x1
					mov ecx, esp
					mov edx, 0xD
					int 0x80

					""")

'''
2. Print a user entered string (from stdin) to stdout. 
'''
shellcode2 = asm("""xor ebx, ebx
					mov eax, 0x3
					sub esp, 0xFF
					mov ecx, esp
					mov edx, 0xFF
					int 0x80

					mov edx, eax
					mov eax, 0x4
					mov ebx, 0x1
					int 0x80

					add esp, 0xFF
					""")

'''
3. Open a file called flag.txt, copy the first 10 bytes into a buffer on the stack, print the contents of the file, and then close the file 
flag.txt backwards ascii - 7478742e 67616c66
'''
shellcode3 = asm("""
					xor eax, eax
					push eax
					push 0x7478742e
					push 0x67616c66

					mov eax, 0x5
					mov ebx, esp
					xor ecx, ecx
					xor edx, edx
					int 0x80

					sub esp, 0xA

					mov ebx, eax
					mov eax, 0x3
					mov ecx, esp
					mov edx, 0xA
					int 0x80

					mov edx, eax
					mov eax, 0x4
					mov ebx, 0x1
					int 0x80

					add esp, 0xA

					""")

'''
4. Transcribe the below code into assembly 

counter = 0
while(1):
    if (counter >= 10){ 
        printf("You win!\n"); 
        break; 
    } else {
        printf("%d\n",counter); 
        counter += 1; 
    }
}

should print 0-9 on new lines and then You Win! on new line
'''
shellcode4 = asm("""  """)

shellcode = shellcode3
print(len(shellcode), shellcode)

p.sendline(shellcode)

p.interactive()
