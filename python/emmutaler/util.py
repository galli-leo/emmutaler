import idc
import idaapi
import ida_loader
import ida_idp

def get_plugin_args() -> list:
    opts = ida_loader.get_plugin_options("emmu")
    return opts.split(":")

def get_args() -> list:
    if len(idc.ARGV) < 1:
        return []
    return idc.ARGV[0].split(" ")