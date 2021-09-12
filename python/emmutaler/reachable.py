from typing import Dict, List, Set, Tuple
import idaapi
import ida_funcs
import ida_bytes
import ida_ua
import ida_name
import ida_xref
import ida_gdl
from emmutaler.log import get_logger
from emmutaler.util import get_func, FuncLoc, func_str

log = get_logger("reachable")

def get_cfg(func: ida_funcs.func_t) -> ida_gdl.qflow_chart_t:
    return ida_gdl.qflow_chart_t("", func, idaapi.BADADDR, idaapi.BADADDR, 0)

class Reachability:
    def __init__(self, nono_bbs = []):
        self.log = get_logger("reachable.Reachability")
        self.reachable = set()
        self.fns: Dict[int, ida_funcs.func_t] = {}
        self.fns_reached: Dict[int, Tuple[ida_funcs.func_t, List[str]]] = {}
        self.panic_fns: Dict[int, bool] = {}
        self.nono_bbs = nono_bbs
        self.path = []
        self.filter_bbs = True
        self.bbs_explored = set()

    def add_panic_fn(self, name):
        func = get_func(name)
        if func is None:
            self.log.error("Could not add panic function %s", name)
            raise Exception
        self.panic_fns[func.start_ea] = True

    def run_addr(self, addr: int, ignore_flow = False):
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
        should_ignore = False
        if ignore_flow:
            is_flow = (insn.get_canon_feature() & idaapi.CF_STOP) != 0
            if is_flow:
                should_ignore = True
        curr = ida_xref.get_first_cref_from(addr)
        while curr != idaapi.BADADDR:
            if should_ignore:
                should_ignore = False
                continue
            self.run(curr)
            curr = ida_xref.get_next_cref_from(addr, curr)
        self.pop_path()

    def __is_panic_fn(self, func: ida_funcs.func_t) -> bool:
        cfg = get_cfg(func)
        if cfg.size() > 1:
            return False
        # get last instruction
        bb: ida_gdl.qbasic_block_t = cfg[0]
        return self.bb_calls_panic(func, bb)
    
    def is_panic_fn(self, func: ida_funcs.func_t) -> bool:
        if func.start_ea in self.panic_fns:
            return self.panic_fns[func.start_ea]
        # check if only one block and that calls panic!
        ret = self.__is_panic_fn(func)
        self.panic_fns[func.start_ea] = ret
        return ret

    def bb_calls_panic(self, func: ida_funcs.func_t, bb: ida_gdl.qbasic_block_t) -> bool:
        last_ea = bb.end_ea - 4
        insn = idaapi.insn_t()
        # TODO: I guess this is not really necessary?
        ret = idaapi.decode_insn(insn, last_ea)
        if ret == 0:
            self.log.error("Failed to decode instruction @ 0x%x, path: %s", last_ea, self.path)
            raise Exception
        if not idaapi.is_call_insn(insn):
            return False
        call_location = insn.Op1.addr
        target_func = get_func(call_location)
        if target_func is not None:
            return self.is_panic_fn(target_func)
        return False

    def allow_bb(self, func: ida_funcs.func_t, bb: ida_gdl.qbasic_block_t) -> bool:
        if not self.filter_bbs:
            return True
        if bb.start_ea in self.nono_bbs:
            return False
        return not self.bb_calls_panic(func, bb)

    def run_range(self, r: idaapi.range_t):
        self.push_path(f"0x{r.start_ea:x} - 0x{r.end_ea:x}")
        for addr in range(r.start_ea, r.end_ea, 4):
            self.run_addr(addr)
        self.pop_path()

    def run_bb(self, func: ida_funcs.func_t, cfg: ida_gdl.qflow_chart_t, bb: ida_gdl.qbasic_block_t, bb_num: int):
        if bb.start_ea in self.bbs_explored:
            return
        self.bbs_explored.add(bb.start_ea)
        if not self.allow_bb(func, bb):
            return
        for addr in range(bb.start_ea, bb.end_ea, 4):
            self.run_addr(addr, True)
        for i in range(cfg.nsucc(bb_num)):
            succ_num = cfg.succ(bb_num, i)
            succ = cfg[succ_num]
            self.run_bb(func, cfg, succ, succ_num)

    def run_func(self, func: ida_funcs.func_t):
        if func.start_ea in self.fns:
            # already processed
            return
        if self.is_panic_fn(func):
            # we want to ignore panic functions
            return
        self.fns[func.start_ea] = func
        self.fns_reached[func.start_ea] = (func, self.path.copy())
        self.push_path(func_str(func))
        # we go over it basic block by basic block!
        cfg = get_cfg(func)
        # TODO: Let's hope bb 0 is actually the starting block!
        self.run_bb(func, cfg, cfg[0], 0)
        # rs = idaapi.rangeset_t()
        # ret = idaapi.get_func_ranges(rs, func)
        # if ret == idaapi.BADADDR:
        #     self.log.error("Could not get ranges for func %s", func_str(func))
        #     return
        # for i in range(rs.nranges()):
        #     r = rs.getrange(i)
        #     self.run_range(r)
        self.pop_path()
        

    def push_path(self, item: str):
        self.path.append(item)

    def pop_path(self):
        self.path.pop()

    def run(self, val: FuncLoc):
        ea = val
        if isinstance(val, str):
            ea = ida_name.get_name_ea(idaapi.BADADDR, val)
        # first check if this is a function
        next_fn = ida_funcs.get_func(ea)
        if next_fn is None:
            # not a function, so just run_addr again!
            self.run_addr(ea)
        else:
            # actually function, so call __run
            self.run_func(next_fn)

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