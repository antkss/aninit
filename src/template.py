#!/usr/bin/env python3
import pwn

{bindings}
pwn.context.log_level='debug'
pwn.context.terminal = ["foot"]
if pwn.args.REMOTE:
    p = pwn.remote("addr", 1337)
else:
    p = pwn.gdb.debug({proc_args},"""

                    """)

sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)


if __name__ == "__main__":
    # p = conn()







    # good luck pwning :)
    p.interactive()
