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


def read_value(dbg: DebugAdapter.DebugAdapter,
               reg: Optional[str], offset: Optional[int]):
    """Read the requested value from the debug adapter.

    If only reg is specified, gets the value of that register.
    If only offset is specified, reads a 64-bit int from memory at the address.
    If reg+offset is specified, reads a 64-bit int from memory at [reg+offset]

    DebugAdapter will raise exceptions if you do something wrong
    """
    if reg is not None and offset is None:
        return dbg.reg_read(reg)
    elif offset is not None:
        if reg is None:
            addr = 0
        if reg is not None:
            addr = dbg.reg_read(reg)
        #print('DBG: reading addr 0x%x+0x%x (0x%x)' % (addr, offset, addr+offset))
        addr += offset

        data = dbg.mem_read(addr, 8)
        return struct.unpack('<Q', data)[0]
    else:
        raise Exception('[!] Must specify at least one of reg or offset arguments')


def get_value_at(target_file: str, args: List[str],
                 reg: Optional[str], offset: Optional[int],
                 breakpoint_addr: int, breakpoint_times: int=0) -> int:
    """Run the target to the specified addr and read the requested value.

    If only reg is specified, gets the value of that register.
    If only offset is specified, reads a 64-bit int from memory at the address.
    If reg+offset is specified, reads a 64-bit int from memory at [reg+offset]
    """
    value_read = None
    times_hit = 0

    dbg = _get_debug_adapter()
    dbg.exec(target_file, args)

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
        elif reason == DebugAdapter.STOP_REASON.PROCESS_EXITED:
            break
        else:
            print('[!] Unexpected stop reason: %s' % str(reason))
            break
    dbg.quit()

    if value_read is None:
        if times_hit == 0:
            raise Exception('[!] Never hit requested breakpoint')
        elif times_hit < breakpoint_times:
            raise Exception('[!] Only hit breakpoint %d times, requested read after %d' %
                            (times_hit, breakpoint_times))

    return value_read


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
        offset = int(offset, 16)
    else:
        try:
            offset = int(read_target, 16)
        except ValueError:
            reg = read_target

    value = get_value_at(target_file, args, reg, offset, breakpoint_addr)
    print('[+] Value for "%s" @ 0x%x: 0x%x' % (read_target, breakpoint_addr, value))

    print('[*] Done.')
