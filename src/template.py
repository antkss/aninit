#!/usr/bin/env python3
from pwn import *
import warnings
warnings.filterwarnings("ignore")
import signal
def handle(signum, frame):
    import os
    os.system("killall gdb")
    exit()
signal.signal(signal.SIGINT, handle)
{bindings}
# context.log_level='debug'
context.terminal = ["foot"]
# p = remote("addr", 1337)
p = process({proc_args})
def gdbs():
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

