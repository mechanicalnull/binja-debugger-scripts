#!/usr/bin/env python3
# By mechanicalnull, for funsies

"""
Use differential debugging to find the first divergence between two runs.

Envisioned use case: Detect where one input first causes a difference in
execution vs another.

Written for well-behaved targets.
"""

import os
import sys
import time
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


def _rebase_bv(bv: BinaryView, dbg: DebugAdapter.DebugAdapter) -> BinaryView:
    """Get a rebased BinaryView for support of ASLR compatible binaries."""
    new_base = dbg.target_base()
    if core_ui_enabled() and new_base != bv.start:
        dbg.quit()
        raise Exception('[!] Can\'t do necessary rebase in GUI, try headless operation')

    new_bv = bv.rebase(new_base)
    if new_bv is None:  # None if rebasing is unecessary
        return bv
    print('[*] Rebasing bv from 0x%x to 0x%x' % (bv.start, new_base))
    new_bv.update_analysis_and_wait()  # required after rebase
    return new_bv


def get_block_path(bv: BinaryView, target_file: str, args: List[str] = []) -> List[int]:
    """Collect the list of basic blocks hit in order.

    NOTE: this won't record coverage on addresses not defined as code and
    software breakpoints can potentially cause issues if the target does
    unfriendly things, like read it's own code, overlap blocks, or split
    instructions.
    """
    dbg = _get_debug_adapter()
    dbg.exec(target_file, args)

    bv = _rebase_bv(bv, dbg)

    breakpoints = set()
    for block in bv.basic_blocks:
        if block.start not in breakpoints:
            dbg.breakpoint_set(block.start)
            breakpoints.add(block.start)

    block_path = []
    while True:
        (reason, _) = dbg.go()  # second item in tuple "data" unused
        if reason == DebugAdapter.STOP_REASON.BREAKPOINT:
            stop_addr = _get_pc(dbg)
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


def get_first_divergence(bv: BinaryView, target_file: str, args_1: List[str], args_2: List[str]) -> Optional[int]:
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

    STANDALONE_USAGE = 'USAGE: %s <target_file> [args1] -- [args2]' % sys.argv[0]
    STANDALONE_USAGE += '\nNOTE: the double dash is mandatory for standalone usage'
    if len(sys.argv) < 3 or '--' not in sys.argv:
        print(STANDALONE_USAGE)
        exit(0)

    target_file = sys.argv[1]
    remaining_args = sys.argv[2:]
    doubledash_index = remaining_args.index('--')
    args_1 = remaining_args[:doubledash_index]
    args_2 = remaining_args[doubledash_index+1:]

    print('[*] Loading BinaryView of %s' % target_file)
    start_time = time.time()
    bv = BinaryViewType.get_view_of_file(target_file)
    duration = time.time() - start_time
    print('[*] Analysis finished in %.2f seconds\n' % duration)

    divergence_point = get_first_divergence(bv, target_file, args_1, args_2)
    if divergence_point:
        print('[+] First divergence point: 0x%x' % divergence_point)
    else:
        print('[!] No divergence found!')
    print('[*] Done.')
