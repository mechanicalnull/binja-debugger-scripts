#!/usr/bin/env python3
# By mechanicalnull, for funsies

"""
Demonstrate collecting block coverage via the debugger by setting breakpoints
at each basic block. Written for well-behaved targets.

Envisioned use case: for use with tools like bncov, when you only need a
couple of traces quickly or getting DynamoRIO is an issue.
"""

import os
import sys
import time
from typing import Iterable, List, Set

from binaryninja.binaryview import BinaryViewType, BinaryView
from binaryninja import core_version, core_ui_enabled, user_plugin_path

# Add path for debugger import, needed in standalone headless execution
if not core_ui_enabled():
    sys.path.append(user_plugin_path())
from debugger import DebugAdapter


def write_coverage_file(bv: BinaryView, addresses: Iterable[int], output_filename: str):
    """Save coverage in the simple mod+offset format."""
    module_name = os.path.basename(bv.file.original_filename)
    module_base = bv.start
    with open(output_filename, 'w') as f:
        for addr in addresses:
            f.write("%s+%x\n" % (module_name, addr - module_base))


def _get_debug_adapter() -> DebugAdapter.DebugAdapter:
    """Helper to define type and encapsulate this in case of changes."""
    return DebugAdapter.get_adapter_for_current_system()


def _get_pc(dbg: DebugAdapter.DebugAdapter) -> int:
    pc_names = ['rip', 'eip', 'pc']
    for reg_name in pc_names:
        if reg_name in dbg.reg_list():
            return dbg.reg_read(reg_name)
    raise Exception('[!] No program counter name (%s) found in registers: %s' % (pc_names, dbg.reg_list()))


def get_block_coverage(bv: BinaryView, target_file: str, args: List[str] = []) -> Set[int]:
    """Collect coverage via debugger with breakpoints on starts of basic blocks.

    NOTE: this won't record coverage on addresses not defined as code and
    software breakpoints can potentially cause issues if the target does
    unfriendly things, like read it's own code, overlap blocks, or split
    instructions.
    """
    dbg = _get_debug_adapter()
    dbg.exec(target_file, args)

    breakpoints = set()
    for block in bv.basic_blocks:
        if block.start not in breakpoints:
            dbg.breakpoint_set(block.start)
            breakpoints.add(block.start)

    breakpoints_hit = set()
    while True:
        (reason, _) = dbg.go()  # second item in tuple "data" unused
        if reason == DebugAdapter.STOP_REASON.BREAKPOINT:
            stop_addr = _get_pc(dbg)
            dbg.breakpoint_clear(stop_addr)
            breakpoints_hit.add(stop_addr)
        elif reason == DebugAdapter.STOP_REASON.PROCESS_EXITED:
            #print('[+] Target exited cleanly')
            break
        else:
            print('[!] Unexpected stop reason: %s' % str(reason))
            break
    dbg.quit()

    return breakpoints_hit


def collect_and_save_coverage(bv: BinaryView, output_filename: str, args: List[str] = []) -> bool:
    """Helpful single-function wrapper to get block coverage using the debugger.

    Throws exception on errors, returns False if no coverage is found, True on success."""

    coverage = get_block_coverage(bv, bv.file.original_filename, args)
    if len(coverage) == 0:
        return False

    write_coverage_file(bv, coverage, output_filename)

    return True


if __name__ == '__main__':

    STANDALONE_USAGE = 'USAGE: %s <target_file> [args]' % sys.argv[0]
    if len(sys.argv) == 1:
        print(STANDALONE_USAGE)
        exit(0)

    target_file = sys.argv[1]
    args = []
    if len(sys.argv) > 2:
        args = sys.argv[2:]

    print('[*] Loading BinaryView of %s' % target_file)
    start_time = time.time()
    bv = BinaryViewType.get_view_of_file(target_file)
    bv.update_analysis_and_wait()
    duration = time.time() - start_time
    print('[*] Analysis finished in %.2f seconds\n' % duration)

    start_time = time.time()
    blocks_hit = get_block_coverage(bv, target_file, args)
    duration = time.time() - start_time
    print('[*] %d blocks covered in %.2f seconds' % (len(blocks_hit), duration))

    coverage_file = os.path.join(os.path.dirname(__file__), 'example.modcov')
    write_coverage_file(bv, blocks_hit, coverage_file)
    print('[+] Wrote %d blocks covered to "%s"' % (len(blocks_hit), coverage_file))
    print('[*] Done!')
