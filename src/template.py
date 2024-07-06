#!/usr/bin/env python3
from pwn import *

{bindings}
# context.log_level='debug'
context.terminal = ["alacritty","-e"]
if args.REMOTE:
    p = remote("addr", 1337)
else:
    p = process({proc_args})
    gdb.attach(p, gdbscript="""

               """)
    # p = gdb.debug({proc_args},"""
    #
    #                 """)

sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)









p.interactive()
# good luck pwning :)

