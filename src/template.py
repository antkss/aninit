#!/usr/bin/env python3
from pwn import *
import warnings
warnings.filterwarnings("ignore")
{bindings}
# context.log_level='debug'
# p = remote("addr", 1337)
p = process({proc_args})
script="""
"""
def GDB():
    context.terminal = ["alacritty", "-e"]
    gdb.attach(p, gdbscript=script)
    input("enter to continue-> ")
    # p = gdb.debug({proc_args}, gdbscript=script)
    # return p
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)









p.interactive()
# good luck pwning :)

