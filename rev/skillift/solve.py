from pwn import *


tmp4 = 0x5443474D489DFDD3
tmp3 = tmp4 + 12345678
tmp2 = tmp3 ^ int.from_bytes(b'HACKERS!', 'big')
tmp1 = ror(tmp2, 5, 64)
key = hex(tmp1)

r = remote('chall.glacierctf.com', 13375)
r.sendlineafter(b'key', key.encode())
r.interactive()

# gctf{V3r1log_ISnT_SO_H4rd_4fTer4ll_!1!}
