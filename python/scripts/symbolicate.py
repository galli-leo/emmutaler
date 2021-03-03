import idaapi
from emmutaler.log import get_logger
from emmutaler.fbs.Symbol import Symbol, SymbolT
from emmutaler.fbs.MetaState import MetaState
import ida_funcs
import ida_name
import ida_entry
import ida_bytes
import ida_loader
import ida_typeinf
import idautils
from emmutaler.meta_file import load_meta_t, save_meta
import flatbuffers
log = get_logger(__name__)

idaapi.auto_wait()

fname = idaapi.get_input_file_path() + ".emmu"
meta = load_meta_t(fname)
meta.symbols = []
for ea, name in idautils.Names():
    # log.info("Have name: %s", name)
    symb = SymbolT()
    # change name, so that we can import / link it!
    act_name = name
    name = "rom_" + name
    symb.name = name
    symb.start = ea
    symb.end = symb.start + ida_bytes.get_item_size(ea)
    func = ida_funcs.get_func(ea)
    if func is not None:
        func: ida_funcs.func_t
        symb.end = func.end_ea
    file_start = ida_loader.get_fileregion_offset(symb.start)
    if file_start == -1:
        log.warn("Symbol %s had -1 for file offset.", symb.name)
    else:
        symb.fileStart = file_start
    file_end = ida_loader.get_fileregion_offset(symb.end)
    if file_end == -1:
        log.warn("Symbol %s had -1 for file end offset", symb.name)
    else:
        symb.fileEnd = file_end
    if not ida_name.set_name(ea, name):
        log.warning("Unable to change the name of %s", name)
    symb.cDefinition = ida_typeinf.print_type(symb.start, ida_typeinf.PRTYPE_SEMI)
    ida_name.set_name(ea, act_name)
    # symb.address = ea
    meta.symbols.append(symb)
meta.state = MetaState.SymbolsDefined
log.info("Done with symbols, saving meta file!")
save_meta(fname, meta)
idaapi.qexit(0)