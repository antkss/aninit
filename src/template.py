#!/usr/bin/env python3
from pwn import *

{bindings}
def conn():
    if args.REMOTE:
        p = remote("addr", 1337)
    else:
        context.terminal = ["foot"]
        p = process({proc_args})
        gdb.attach(p, gdbscript='''

        ''')
    return p
info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)



if __name__ == "__main__":
    p = conn()







    # good luck pwning :)
    p.interactive()
