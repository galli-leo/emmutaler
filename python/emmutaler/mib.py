from emmutaler.log import get_logger
import idaapi
import ida_name
import idautils
import ida_hexrays
import ida_xref
from enum import Enum

class OIDType(Enum):
    Uint32 = 0
    Int32 = 1
    Uint64 = 2
    Int64 = 3
    Bool = 4
    String = 5
    Struct = 6
    Indirect = 7

class OIDQualifier(Enum):
    Nix = 0
    DataIndirect = 1
    Function = 2
    Array = 3
    Weak = 4
    BigUnknown = 16

class Mib:
    """Represents a MIB (no idea what that is, but seems config values?)

    struct is as follows:

    struct mib_node
    {
    uint32_t node_oid;
    mib_oid_flags node_type;
    union mib_value node_data;
    __int64 field_18;
    };

    """
    def __init__(self, address) -> None:
        self.log = get_logger(__name__+".Mib")
        self.addr = address
        self.load()

    @property
    def oid_type(self) -> OIDType:
        type_num = (self.type >> 16) & 0xff
        return OIDType(type_num)

    @property
    def qualifier(self) -> OIDQualifier:
        qual_num = (self.type >> 24) & 0xff
        return OIDQualifier(qual_num)

    def load(self):
        self.log.info("Loading mib data from 0x%x", self.addr)
        self.oid = idaapi.get_dword(self.addr)
        self.type = idaapi.get_dword(self.addr + 4)
        self.value = idaapi.get_qword(self.addr + 8)
        # TODO: Rest of the fields.

    def build_cmt(self) -> str:
        return f"Value: 0x{self.value:x}, Type: {self.oid_type.name} ({self.qualifier.name})"

BEGIN_NAME = "mib_linker_set_begin"
END_NAME = "mib_linker_set_limit"
TOP_FUNC = ["mib_get_size", "mib_get_string"]

class MibHandler:
    def __init__(self) -> None:
        self.log = get_logger(__name__+".MibHandler")
        self.mibs = {}

    def load_by_name(self):
        start = ida_name.get_name_ea(idaapi.BADADDR, BEGIN_NAME)
        end = ida_name.get_name_ea(idaapi.BADADDR, END_NAME)
        if start != idaapi.BADADDR and end != idaapi.BADADDR:
            self.load(start, end)
        else:
            self.log.warning("Could not find address for names %s, %s", BEGIN_NAME, END_NAME)

    def load(self, address, limit):
        self.log.info("Loading MIBs from address: 0x%x", address)
        for ptr in range(address, limit, 8):
            ptr_val = idaapi.get_qword(ptr)
            if ptr_val != idaapi.BADADDR:
                mib = Mib(ptr_val)
                self.mibs[mib.oid] = mib
        self.log.info("Loaded %d mibs", len(self.mibs))

    def comment_usages(self):
        self.log.info("Commenting on usages of %s", TOP_FUNC)
        for func_name in TOP_FUNC:
            func_addr = ida_name.get_name_ea(idaapi.BADADDR, func_name)
            if func_addr == idaapi.BADADDR:
                self.log.warning("Could not find top func!")
                return
            xrefs = ida_xref.get_first_cref_to(func_addr)
            for i in range(100):
                if xrefs == idaapi.BADADDR:
                    break
                self.log.info("Trying to decompile function at 0x%x", xrefs)
                cfunc: idaapi.cfunc_t = ida_hexrays.decompile(xrefs)
                visitor = mib_visitor_t(self, cfunc)
                visitor.apply_to(cfunc.body, None)
                if xrefs in visitor.found_mibs:
                    mib = visitor.found_mibs[xrefs]
                    tl = idaapi.treeloc_t()
                    tl.ea = xrefs
                    tl.itp = idaapi.ITP_SEMI
                    cfunc.set_user_cmt(tl, mib.build_cmt())
                    cfunc.save_user_cmts()
                else:
                    self.log.warning("could not find mib for address: 0x%x", xrefs)
                xrefs = ida_xref.get_next_cref_to(func_addr, xrefs)

class mib_visitor_t(idaapi.ctree_visitor_t):
    def __init__(self, mib_handler: MibHandler, func: idaapi.cfunc_t):
        self.mib_handler = mib_handler
        self.func = func
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_PARENTS)
        self.found_mibs = {}
        return

    def visit_expr(self, expr: ida_hexrays.cexpr_t):
        if expr.op != ida_hexrays.cot_call:
            return 0

        method_name = idaapi.get_func_name(expr.x.obj_ea)
        if expr.a.size() > 0:
            args = expr.a
            oid_arg: idaapi.carg_t = args[0]
            if oid_arg.op == ida_hexrays.cot_num:
                oid_val = oid_arg.numval()
                if oid_val in self.mib_handler.mibs:
                    mib = self.mib_handler.mibs[oid_val]
                    self.found_mibs[expr.ea] = mib
                else:
                    self.mib_handler.log.warning("Could not find mib with oid 0x%x", oid_val)
            else:
                self.mib_handler.log.warning("Argument %s could not be converted to num!", oid_arg.type)

        return 0

def annotate_mib():
    pass