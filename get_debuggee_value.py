#!/usr/bin/env python3
# By mechanicalnull, for funsies

"""
Get a register or memory value from the debuggee at a given address.

Envisioned use case: Compare register/memory values across inputs.

This is only a basic implementation but can easily be extended.

Written for well-behaved targets on little-endian systems.
"""

import os
import sys
import time
import struct
from typing import Optional, List

from binaryninja.binaryview import BinaryViewType, BinaryView
from binaryninja import core_ui_enabled, user_plugin_path

# Add path for debugger import, needed in standalone headless execution
if not core_ui_enabled():
    sys.path.append(user_plugin_path())
from debugger import DebugAdapter


def _get_debug_adapter() -> DebugAdapter.DebugAdapter:
    """Helper to define type and encapsulate this in case of changes."""
    return DebugAdapter.get_adapter_for_current_system()


def _get_pc(dbg: DebugAdapter.DebugAdapter) -> int:
    pc_names = ['rip', 'eip', 'pc']
    for reg_name in pc_names:
        if reg_name in dbg.reg_list():
            return dbg.reg_read(reg_name)
    raise Exception('[!] No program counter name (%s) found in registers: %s' %
                    (pc_names, dbg.reg_list()))


def _rebase_if_needed(dbg: DebugAdapter, addr: int) -> int:
    """Attempt "blind rebase": guessing that if we can't read it, try a rebase."""
    try:
        _ = dbg.mem_read(addr, 1)
    except DebugAdapter.GeneralError:
        current_base = dbg.target_base()
        new_addr = addr + current_base
        try:
            _ = dbg.mem_read(new_addr, 1)
        except DebugAdapter.GeneralError:
            dbg.quit()
            raise Exception('[!] Couldn\'t read or rebase address 0x%x (current base: 0x%x)' % (addr, current_base))
        print('[*] Couldn\'t read 0x%x, rebased to 0x%x' % (addr, new_addr))
        addr = new_addr
    return addr


def read_value(dbg: DebugAdapter.DebugAdapter,
               reg: Optional[str], offset: Optional[int]) -> Optional[int]:
    """Read the requested value from the debug adapter.

    If only reg is specified, gets the value of that register.
    If only offset is specified, reads a 64-bit int from memory at the address.
    If reg+offset is specified, reads a 64-bit int from memory at [reg+offset]

    Will try to rebase address if you only supply and offset and it appears to
    be within the target module.

    DebugAdapter will raise exceptions if you do something wrong.
    """
    if reg is not None and offset is None:
        return dbg.reg_read(reg)
    elif offset is not None:
        if reg is None:
            addr = _rebase_if_needed(dbg, offset)
        if reg is not None:
            addr = dbg.reg_read(reg)
            addr += offset
        #print('DBG: reading addr 0x%x+0x%x (0x%x)' % (addr, offset, addr+offset))

        data = dbg.mem_read(addr, 8)
        return struct.unpack('<Q', data)[0]
    else:
        raise Exception('[!] Must specify at least one of reg or offset arguments')


def get_value_at(dbg: DebugAdapter.DebugAdapter,
                 reg: Optional[str], offset: Optional[int],
                 breakpoint_addr: int, breakpoint_times: int=0) -> int:
    """Run the DebugAdapter to the specified addr and read the requested value.

    If only reg is specified, gets the value of that register.
    If only offset is specified, reads a 64-bit int from memory at the address.
    If reg+offset is specified, reads a 64-bit int from memory at [reg+offset]

    Will try to rebase address if you only supply and offset and it appears to
    be within the target module.

    Raises exceptions on errors, for example if breakpoint_addr isn't hit or
    is hit fewer times than specified.
    """
    value_read = None
    times_hit = 0

    dbg.breakpoint_set(breakpoint_addr)

    while True:
        (reason, _) = dbg.go()  # second item in tuple "data" unused
        if reason == DebugAdapter.STOP_REASON.BREAKPOINT:
            stop_addr = _get_pc(dbg)
            dbg.breakpoint_clear(stop_addr)
            if times_hit < breakpoint_times:
                dbg.step_into()
                dbg.breakpoint_set(stop_addr)
                times_hit += 1
            else:
                value_read = read_value(dbg, reg, offset)
                break
        elif reason == DebugAdapter.STOP_REASON.PROCESS_EXITED:
            break
        else:
            print('[!] Unexpected stop reason: %s' % str(reason))
            break

    if value_read is None:
        if times_hit == 0:
            raise Exception('[!] Never hit requested breakpoint')
        elif times_hit < breakpoint_times:
            raise Exception('[!] Only hit breakpoint %d times, requested read after %d' %
                            (times_hit, breakpoint_times))
        else:
            raise Exception('[!] Unexpected error: Breakpoint hit but value_read is None')

    return value_read

def get_debuggee_value(target_file: str, args: List[str],
                       reg: Optional[str], offset: Optional[int],
                       breakpoint_offset: int, breakpoint_times: int=0) -> int:
    """Start & run target to the specified offset and get the requested value.

    If only reg is specified, gets the value of that register.
    If only offset is specified, reads a 64-bit int from memory at the address.
    If reg+offset is specified, reads a 64-bit int from memory at [reg+offset]

    Will try to rebase addresses if they appear to be an offset into the target.

    Returns value on success, raises Exception otherwise.
    """
    dbg = _get_debug_adapter()
    dbg.exec(target_file, args)

    breakpoint_address = _rebase_if_needed(dbg, breakpoint_offset)

    value = get_value_at(dbg, reg, offset, breakpoint_address)

    dbg.quit()

    return value


if __name__ == '__main__':

    STANDALONE_USAGE = 'USAGE: %s <target_file> BKPT_ADDR <REG | ADDR | REG+OFFSET> [args]' % sys.argv[0]
    STANDALONE_USAGE += '\nNOTE: Do not use spaces between reg+offset; addresses/offsets are in hex'
    if len(sys.argv) < 4:
        print(STANDALONE_USAGE)
        exit(0)

    target_file = sys.argv[1]
    breakpoint_addr = int(sys.argv[2], 16)
    read_target = sys.argv[3]
    if len(sys.argv) == 4:
        args = []
    else:
        args = sys.argv[4:]

    reg = None
    offset = None
    if '+' in read_target:
        reg, offset = read_target.split('+')
        int_offset = int(offset, 16)
    else:
        try:
            int_offset = int(read_target, 16)
        except ValueError:
            reg = read_target

    value = get_debuggee_value(target_file, args, reg, int_offset, breakpoint_addr)
    print('[+] Value for "%s" @ 0x%x: 0x%x' % (read_target, breakpoint_addr, value))

    print('[*] Done.')
