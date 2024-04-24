[![Checks Status](https://github.com/io12/pwninit/workflows/checks/badge.svg)](https://github.com/io12/pwninit/actions)
[![Deploy Status](https://github.com/io12/pwninit/workflows/deploy/badge.svg)](https://github.com/io12/pwninit/actions)
[![](https://img.shields.io/crates/v/pwninit)](https://crates.io/crates/pwninit)
[![](https://docs.rs/pwninit/badge.svg)](https://docs.rs/pwninit)

# `aninit`

remake pwninit

## Features

- Set challenge binary to be executable
- Download a linker (`ld-linux.so.*`) that can segfaultlessly load the provided libc
- Download debug symbols and unstrip the libc
- Patch the binary with [`patchelf`](https://github.com/NixOS/patchelf) to use
  the correct RPATH and interpreter for the provided libc
- Fill in a template pwntools solve script
- replace libc download server
- add unstripping with pwn.libcdb

## Usage

### Short version

Run `aninit`

or

Run `aninit` in a directory with the relevant files and it will detect which ones are the binary, libc, and linker. If the detection is wrong, you can specify the locations with `-b binary`, `-l libc.so`, and `-d ld.so`.

#### Custom `solve.py` template

If you don't like the default template, you can use your own. Just specify `--template-path <path>`. Check [template.py](src/template.py) for the template format. The names of the `binary`, `libc`, and `ld` bindings can be customized with `--template-bin-name`, `--template-libc-name`, and `--template-ld-name`.

##### Persisting custom `solve.py`

You can make `aninit` load your custom template automatically by adding an alias to your `~/.bashrc`.

###### Example

```bash
alias aninit='aninit --template-path ~/.config/pwninit-template.py --template-bin-name e'
```

## Install


### Download
Download binary from the [releases page](https://github.com/antkss/pwninit/releases).


Note that `openssl`, `liblzma`, and `pkg-config` are required for the build.

## Example

```sh
🍎 >> ls
ld-2.23.so*  libc.so.6*  vuln*  vuln.i64
[  home/as/Music  ]
🍎 >> aninit 
bin: ./vuln
libc: ./libc.so.6
ld: ./ld-2.23.so

output: [*] Using cached data from '/home/as/.cache/.pwntools-cache-3.11/libcdb_dbg/build_id/131c254aed46e6a24cb08f3abe802ea0ef50e5f9'
[x] Starting local process '/usr/bin/eu-unstrip'
[+] Starting local process '/usr/bin/eu-unstrip': pid 94704
[x] Receiving all data
[x] Receiving all data: 0B
[+] Receiving all data: Done (0B)
[*] Process '/usr/bin/eu-unstrip' stopped with exit code 0 (pid 94704)

copying ./vuln to ./vulne
running patchelf on ./vulne
writing solve.py stub
[  home/as/Music  ]
🍎 >> 
```

`solve.py`:

```python
#!/usr/bin/env python3
from pwn import *

exe = ELF("./vulne")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.23.so")
def conn():
    if args.REMOTE:
        p = remote("addr", 1337)
    else:
        context.terminal = ["foot"]
        p = process([exe.path])
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
```
## why remake ?
- because the server that author is using so hilariously slow 
