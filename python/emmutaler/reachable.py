from typing import List, Set
import idaapi
import ida_funcs
import ida_bytes
import ida_ua
import ida_xref
from emmutaler.log import get_logger
from emmutaler.util import get_func, FuncLoc, func_str

log = get_logger("reachable")

class Reachability:
    def __init__(self, val: FuncLoc):
        self.log = get_logger("reachable.Reachability")
        self.val = val
        self.reachable = set()
        self.fns = set()
        self.start = get_func(self.val)
        self.path = []

    def run_addr(self, addr: int):
        if addr in self.reachable:
            return
        self.reachable.add(addr)
        self.push_path(f"0x{addr:x}")
        insn = idaapi.insn_t()
        # TODO: I guess this is not really necessary?
        ret = idaapi.decode_insn(insn, addr)
        if ret == 0:
            self.log.error("Failed to decode instruction @ 0x%x, path: %s", addr, self.path)
            raise Exception
            return
        # iterate over all xrefs
        # should always be passing of control!
        curr = ida_xref.get_first_cref_from(addr)
        while curr != idaapi.BADADDR:
            # first check if this is a function
            next_fn = ida_funcs.get_func(curr)
            if next_fn is None:
                # not a function, so just run_addr again!
                self.run_addr(curr)
            else:
                # actually function, so call __run
                self.__run(next_fn)
            curr = ida_xref.get_next_cref_from(addr, curr)
        self.pop_path()
        

    def run_range(self, r: idaapi.range_t):
        self.push_path(f"0x{r.start_ea:x} - 0x{r.end_ea:x}")
        for addr in range(r.start_ea, r.end_ea, 4):
            self.run_addr(addr)
        self.pop_path()

    def __run(self, func: ida_funcs.func_t):
        if func.start_ea in self.fns:
            # already processed
            return
        self.fns.add(func.start_ea)
        self.push_path(func_str(func))
        rs = idaapi.rangeset_t()
        ret = idaapi.get_func_ranges(rs, func)
        if ret == idaapi.BADADDR:
            self.log.error("Could not get ranges for func %s", func_str(func))
            return
        for i in range(rs.nranges()):
            r = rs.getrange(i)
            self.run_range(r)
        self.pop_path()

    def push_path(self, item: str):
        self.path.append(item)

    def pop_path(self):
        self.path.pop()

    def run(self):
        self.__run(self.start)
        return self.reachable

def get_reachable(val: FuncLoc) -> Set[int]:
    """Get all reachable addresses starting at function identified by val.
    This is a wrapper around the Reachability class.

    Parameters
    ----------
    val : FuncLoc
        The location of the starting function.

    Returns
    -------
    List[int]
        Addresses reachable.
    """
    r = Reachability(val)
    return r.run()