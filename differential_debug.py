#!/usr/bin/env python3
# By mechanicalnull, for funsies

"""
Use differential debugging to find the first divergence between two runs.

Written for well-behaved targets.
"""

import os
import sys
import time
from typing import Optional, List

from binaryninja.binaryview import BinaryViewType, BinaryView
from binaryninja import core_version, core_ui_enabled, user_plugin_path

# Add path for debugger import, needed in standalone headless execution
if not core_ui_enabled():
    sys.path.append(user_plugin_path())
from debugger import DebugAdapter


def get_debug_adapter() -> DebugAdapter.DebugAdapter:
    """Helper to define type and encapsulate this in case of changes."""
    return DebugAdapter.get_adapter_for_current_system()


def get_pc(dbg: DebugAdapter.DebugAdapter) -> int:
    pc_names = ['rip', 'eip', 'pc']
    for reg_name in pc_names:
        if reg_name in dbg.reg_list():
            return dbg.reg_read(reg_name)
    raise Exception('[!] No program counter name (%s) found in registers: %s' %
                    (pc_names, dbg.reg_list()))


def get_block_path(bv: BinaryView, target_file: str, args: List[str] = []) -> List[int]:
    """Collect the list of basic blocks hit in order.

    NOTE: this won't record coverage on addresses not defined as code and
    software breakpoints can potentially cause issues if the target does
    unfriendly things, like read it's own code, overlap blocks, or split
    instructions.
    """
    dbg = get_debug_adapter()
    dbg.exec(target_file, args)

    breakpoints = set()
    for block in bv.basic_blocks:
        if block.start not in breakpoints:
            dbg.breakpoint_set(block.start)
            breakpoints.add(block.start)

    block_path = []
    while True:
        (reason, _) = dbg.go()  # second item in tuple "data" unused
        if reason == DebugAdapter.STOP_REASON.BREAKPOINT:
            stop_addr = get_pc(dbg)
            block_path.append(stop_addr)
            dbg.breakpoint_clear(stop_addr)
            dbg.step_into()
            dbg.breakpoint_set(stop_addr)
            #print('DBG: Hit 0x%x' % stop_addr)

        elif reason == DebugAdapter.STOP_REASON.PROCESS_EXITED:
            #print('[+] Target exited cleanly')
            break
        else:
            print('[!] Unexpected stop reason: %s' % str(reason))
            break
    dbg.quit()

    return block_path


def compare_runs(bv: BinaryView, target_file: str, args_1: List[str], args_2: List[str]) -> Optional[int]:
    """Return the start of the block after which the two runs diverge or None."""

    start_time = time.time()
    path_1 = get_block_path(bv, target_file, args_1)
    duration = time.time() - start_time
    print('[*] Path 1 (%d blocks) recorded in %.2f seconds' %
          (len(path_1), duration))

    start_time = time.time()
    path_2 = get_block_path(bv, target_file, args_2)
    duration = time.time() - start_time
    print('[*] Path 2 (%d blocks) recorded in %.2f seconds' %
          (len(path_2), duration))

    divergence = None
    for i in range(min(len(path_1), len(path_2))):
        if path_1[i] != path_2[i]:
            divergence = path_1[i-1]
            print('[*] First divergence at %d blocks in:' % i)
            print('    Path 1: 0x%x' % path_1[i])
            print('    Path 2: 0x%x' % path_2[i])
            print('    Shared predecessor block: 0x%x' % path_1[i-1])
            break

    # handle cases where the traces are the same until one dies
    if divergence is None and len(path_1) != len(path_2):
        if len(path_1) < len(path_2):
            shorter = path_1
        else:
            shorter = path_2
        divergence = shorter[-1]

    return divergence


if __name__ == '__main__':

    USAGE = '%s <target_file> [args1] -- [args2]' % sys.argv[0]
    USAGE += '\nNOTE: the double dash is mandatory for standalone usage'
    if len(sys.argv) < 3 or '--' not in sys.argv:
        print(USAGE)
        exit(0)

    target_file = sys.argv[1]
    remaining_args = sys.argv[2:]
    doubledash_index = remaining_args.index('--')
    args_1 = remaining_args[:doubledash_index]
    args_2 = remaining_args[doubledash_index+1:]
    print(f'args_1 {args_1}')
    print(f'args_2 {args_2}')

    print('[*] Loading BinaryView of %s' % target_file)
    start_time = time.time()
    bv = BinaryViewType.get_view_of_file(target_file)
    bv.update_analysis_and_wait()
    duration = time.time() - start_time
    print('[*] Analysis finished in %.2f seconds\n' % duration)

    divergence_point = compare_runs(bv, target_file, args_1, args_2)
    if divergence_point:
        print('[+] First divergence point: 0x%x' % divergence_point)
    else:
        print('[!] No divergence found!')
    print('[*] Done.')
