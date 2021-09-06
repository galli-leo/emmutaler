from typing import Union
import idc
import idaapi
import ida_loader
import ida_idp
import ida_funcs
import ida_name
import ida_bytes

def get_plugin_args() -> list:
    opts = ida_loader.get_plugin_options("emmu")
    if opts is None:
        return []
    return opts.split(":")

def get_args() -> list:
    if len(idc.ARGV) < 1:
        return get_plugin_args()
    return idc.ARGV[0].split(" ")

FuncLoc = Union[int, str]

def get_func(val: FuncLoc) -> ida_funcs.func_t:
    from emmutaler.log import get_logger
    log = get_logger("util")
    """Get the function either by name or address.
    The address does not necessarily need to be the start of the function, it can also point inside it.
    This can be tricky with function chunks though.

    Parameters
    ----------
    val : Union[int, str]
        The address or name.

    Returns
    -------
    ida_funcs.func_t
        The function.
    """
    addr = val
    if isinstance(val, str):
        addr = ida_name.get_name_ea(idaapi.BADADDR, val)
    log.debug("Resolving function @ 0x%x", addr)
    return ida_funcs.get_func(addr)
    
def func_str(f: idaapi.func_t) -> str:
    name = ida_funcs.get_func_name(f.start_ea)
    return f"<{name} @ 0x{f.start_ea:x}>"