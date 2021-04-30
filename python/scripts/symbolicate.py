from io import TextIOWrapper
import idaapi
from emmutaler.log import get_logger
from emmutaler.fbs.Symbol import Symbol, SymbolT
from emmutaler.fbs.MetaState import MetaState
from emmutaler.util import get_args
from emmutaler.typeinf import GenHeader, print_item_type
import ida_funcs
import ida_name
import ida_entry
import ida_bytes
import ida_loader
import ida_typeinf
import idautils
import idc
import ida_ida
from emmutaler.meta_file import load_meta_t, save_meta
import flatbuffers
import os
import sys
import time
import ida_idp
import ida_kernwin
log = get_logger(__name__)

# Don't save anything we do here!
idaapi.process_config_directive("ABANDON_DATABASE=YES")

class SaveHook(idaapi.IDB_Hooks):
    def savebase(self, *args):
        log.info("SAVING DB: %s", args)

save_hooks = SaveHook()
save_hooks.hook()

def main():
    idaapi.auto_wait()
    log.info("Making database readonly!")
    if not ida_ida.inf_set_readonly_idb(True):
        log.warning("Failed to make database readonly!")
    if not ida_ida.inf_readonly_idb():
        log.warning("Failed to make database readonly!")
    args = get_args()

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
            log.debug("Symbol %s had -1 for file offset.", symb.name)
        else:
            symb.fileStart = file_start
        file_end = ida_loader.get_fileregion_offset(symb.end)
        if file_end == -1:
            log.debug("Symbol %s had -1 for file end offset", symb.name)
        else:
            symb.fileEnd = file_end
        # if not ida_name.set_name(ea, name):
        #     log.warning("Unable to change the name of %s", name)
        symb_def = print_item_type(symb.start)
        if symb_def is not None:
            repl_name = act_name
            if act_name[0] == "_":
                repl_name = act_name[1:]
            occ = symb_def.count(repl_name)
            # TODO: Fix this for real!
            if occ > 1:
                repl_name = " " + repl_name
                symb.cDefinition = symb_def.replace(repl_name, " "+name)
            else:
                symb.cDefinition = symb_def.replace(repl_name, name)
            if "rom_" not in symb.cDefinition:
                log.warning("Symbol %s could not fixup c definition %s to have rom_ prefix", symb.name, symb.cDefinition)
        # ida_name.set_name(ea, act_name)
        # symb.address = ea
        meta.symbols.append(symb)
    meta.state = MetaState.SymbolsDefined
    log.info("Done with symbols, saving meta file!")
    save_meta(fname, meta)
    log.info("ARGS: %s", args)
    if len(args) > 1:
        type_file = args[1]
        gen = GenHeader(type_file)
        gen.sys_includes = ["stdint.h"]
        gen.gen()
    idaapi.qexit(0)

if __name__ == "__main__":
    try:
        main()
    except:
        log.exception("Had an error running symbolicate!")