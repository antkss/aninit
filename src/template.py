#!/usr/bin/env python3
from pwn import *
import warnings
warnings.filterwarnings("ignore")
{bindings}
# context.log_level='debug'
# p = remote("addr", 1337)
p = process({proc_args})
def GDB():
    context.terminal = ["foot"]
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

