#!/bin/bash
# my idea with bash script, you can ignore it
# Function to print usage
usage() {
  echo "Usage: $0 <binary> [-l libc] [-ld loader] [-h]"
  echo "Options:"
  echo "  -l    libc"
  echo "  -ld   loader"
  echo "  -h    Print this help message"
  exit 1
}

# Initialize variables
bin="$1"
libc=""
ld=""
shift
# Parse options

while getopts ":l:d:h" opt; do
  case $opt in
    l)
      libc="$OPTARG"
      ;;
    d)
      ld="$OPTARG"
      ;;
    h)
      usage
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      usage
      ;;
  esac
done

# Check if required options are set
if [ -z "$bin" ]; then
  echo "Error: binary are required!"
  usage
fi

binding=""
# Print information based on options
echo "binary: $bin"
# Patch each program file with libc and ld file
if [ -f "${bin}e" ]; then
	echo "patched file exist ! leaving..."
	exit 0
else
	cp $bin "${bin}e"
fi
if [ -z $ld  ]; then
	echo "ld: $ld"
else
	echo "ld: $ld"
	chmod a+x $ld
	patchelf --set-interpreter "$ld" "${bin}e"
	binding="$binding
ld = ELF(\"$ld\")"
fi
if [ -z $libc ]; then
	echo "libc: $libc"
else
python << END
import pwn
pwn.libcdb.unstrip_libc("$libc")
END
	echo "libc: $libc"
	chmod a+x $libc
	if [ $libc == "libc.so.6" ]; then
python << END
import pwn
pwn.libcdb.unstrip_libc("$libc")
END
		patchelf --set-rpath ./ "${bin}e" 
		binding="$binding
libc = ELF(\"libc.so.6\")"
	else
		if [ -f "./libc.so.6" ]; then
			rm ./libc.so.6
		fi
		ln -s $libc ./libc.so.6
		patchelf --set-rpath ./ "${bin}e" 
		binding="$binding
libc = ELF(\"libc.so.6\")"

	fi
fi

if [ -f "./solve.py" ]; then
	echo "solve file exist ! leaving..."
	exit 0
else
echo "#!/usr/bin/env python3

from pwn import *
exe = ELF(\"${bin}e\")
$binding


p = process([exe.path])
def GDB():
    context.terminal = [\"foot\"]
    gdb.attach(p, gdbscript='''



           ''')
info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

# pwning lmao lmao dark bruh
def main():
    GDB()







    p.interactive()


if __name__ == \"__main__\":
    main()" > ./solve.py
chmod a+x ./solve.py
fi
