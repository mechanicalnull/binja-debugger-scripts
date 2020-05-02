#!/usr/bin/env python3
# By mechanicalnull, for funsies

"""
Run the target and observe calls to build a call tree.

Envisioned use case: When static analysis doesn't yield a perfect call tree or
a call tree for a specific input is desired.

Written for well-behaved targets.
"""

import os
import sys
import time
from typing import Optional, List, Tuple, Set, Dict

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


def _breakpoint_function_starts_and_calls(bv: BinaryView, dbg: DebugAdapter) -> Tuple[dict, dict]:
    """Breakpoint functions and callsites, return mappings of addr to func_name."""

    call_breakpoints: Dict[str, str] = {}  # map callsite addrs to function name
    function_breakpoints: Dict[str, str] = {}  # map function start addrs to function name
    for func in bv.functions:
        cur_func = func.name
        func_start = func.start
        if func_start in function_breakpoints:
            old_func = function_breakpoints[func_start]
            raise Exception('[!] Address 0x%x for %s already start for %s' % (func_start, cur_func, old_func))
        function_breakpoints[func_start] = cur_func
        dbg.breakpoint_set(func_start)

        for site in func.call_sites:
            call_addr = site.address
            if call_addr in call_breakpoints:
                old_func = call_breakpoints[call_addr]
                raise Exception('[!] Address 0x%x in "%s" already found in "%s"' %
                                (call_addr, cur_func, old_func))
            call_breakpoints[call_addr] = cur_func
            if call_addr not in function_breakpoints:
                dbg.breakpoint_set(call_addr)

    return function_breakpoints, call_breakpoints


def _check_breakpoints(bv: BinaryView, dbg: DebugAdapter, 
                       addr: int, function_breakpoints: dict, call_breakpoints: dict) -> List[str]:
    """Return [name,] on function start or [caller, callee] on intermodular calls.

    Returns [] otherwise.
    """

    retval = []

    if addr in function_breakpoints:
        cur_func = function_breakpoints[addr]
        #print('[DBG] START function %s @ 0x%x' % (cur_func, addr))
        retval = [cur_func,]  # intentional: this may be overridden below

    if addr in call_breakpoints:
        cur_func = call_breakpoints[addr]
        call_target = _get_pc(dbg)
        target_func_obj = bv.get_function_at(call_target)
        if target_func_obj is None:
            offset = call_target
            if bv.is_valid_offset(offset):
                print('[!] Unknown function at offset 0x%x' % offset)
                target_func = "UNK_%x" % offset
            else:
                target_func = "EXTERNAL_%x" % call_target
        else:
            target_func = target_func_obj.name
        #print('[DBG] CALL from 0x%x in %s -> 0x%x in %s' % (addr, cur_func, call_target, target_func))
        if not target_func.startswith('EXTERNAL_'):
            retval = [cur_func, target_func]

    return retval


def _rebase_bv(bv: BinaryView, dbg: DebugAdapter.DebugAdapter) -> BinaryView:
    """Get a rebased BinaryView for support of ASLR compatible binaries."""
    new_base = dbg.target_base()
    new_bv = bv.rebase(new_base)
    if new_bv is None:
        return bv
    print('[*] Rebasing bv from 0x%x to 0x%x' % (bv.start, new_base))
    new_bv.update_analysis_and_wait()  # required after rebase
    return new_bv


def get_calltree(bv: BinaryView, target_file: str, args: List[str]) -> Dict[str, Set[str]]:
    """Run target and observe calls/returns to build a calltree.

    The calltree maps function names {caller: {callees, ...}, ...}
    Functions that are executed but don't call other functions are represented
    with their name mapping to an empty set.

    Assumes that functions don't overlap.
    """
    dbg = _get_debug_adapter()
    dbg.exec(target_file, args)

    bv = _rebase_bv(bv, dbg)

    function_breakpoints, call_breakpoints = _breakpoint_function_starts_and_calls(bv, dbg)

    calltree: Dict[str, Set[str]] = {}
    while True:
        (reason, _) = dbg.go()  # second item in tuple "data" unused
        if reason == DebugAdapter.STOP_REASON.BREAKPOINT:
            # Move beyond breakpoint
            stop_addr = _get_pc(dbg)
            dbg.breakpoint_clear(stop_addr)
            dbg.step_into()
            dbg.breakpoint_set(stop_addr)

            # Update bookkeeping
            functions_hit = _check_breakpoints(bv, dbg, stop_addr, function_breakpoints, call_breakpoints)
            if len(functions_hit) == 1:
                func_name = functions_hit[0]
                if func_name not in calltree:
                    calltree[func_name] = set()
            elif len(functions_hit) == 2:
                cur_func, target_func = functions_hit
                calltree.setdefault(cur_func, set()).add(target_func)

        elif reason == DebugAdapter.STOP_REASON.PROCESS_EXITED:
            #print('[+] Target exited cleanly')
            break
        else:
            print('[!] Unexpected stop reason: %s' % str(reason))
            break
    dbg.quit()

    return calltree


def print_calltree(calldict: dict):
    """Print a space-indented recursive tree.

    An asterisk after a name indicates the function has already been traversed.
    """
    print('[+] Printing call tree with %d functions:' % len(calldict))
    # It looks nicer to start from obvious entry points
    default_roots = ['WinMain', 'wWinMain', 'main', 'wmain', '_main', '_start']
    root = None
    for root in default_roots:
        if root in calldict:
            break

    def recursive_print_node(cur_node: str, tree: dict, level: int, seen: set) -> Set[str]:
        indent = '    '
        if cur_node in seen:
            print('%s%s*' % (indent * level, cur_node))
            return seen
        print('%s%s' % (indent * level, cur_node))
        seen.add(cur_node)
        children = tree.get(cur_node, [])
        for child_node in sorted(children):
            child_saw = recursive_print_node(child_node, tree, level + 1, seen)
            seen.update(child_saw)
        return seen

    seen: Set[str] = set()
    while True:
        keys_left = calldict.keys() - seen
        if keys_left == set():
            break
        if root is None:
            # pick remaining node with most immediate children
            root = sorted(keys_left, key=lambda k: len(calldict[k]), reverse=True)[0]
        nodes_traversed = recursive_print_node(root, calldict, 0, seen)
        seen.update(nodes_traversed)
        root = None


if __name__ == '__main__':

    STANDALONE_USAGE = 'USAGE: %s <target_file> [args]' % sys.argv[0]
    if len(sys.argv) < 2:
        print(STANDALONE_USAGE)
        exit(0)

    target_file = sys.argv[1]
    remaining_args = sys.argv[2:]

    print('[*] Loading BinaryView of %s' % target_file)
    start_time = time.time()
    bv = BinaryViewType.get_view_of_file(target_file)
    duration = time.time() - start_time
    print('[*] Analysis finished in %.2f seconds\n' % duration)

    start_time = time.time()
    calltree = get_calltree(bv, target_file, remaining_args)
    duration = time.time() - start_time
    print('[*] Calltree collection finished in %.2f seconds\n' % duration)

    print_calltree(calltree)
    print('[*] Done.')
