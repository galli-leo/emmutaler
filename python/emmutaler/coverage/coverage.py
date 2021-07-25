from emmutaler.log import get_logger
from emmutaler.coverage.metadata import *
import ida_funcs
import idautils
import os
import struct

class CoverageDirector:
    def __init__(self) -> None:
        self.funcs: List[FuncMeta] = []
        self.log = get_logger(__name__ + ".Director")

    def init_meta(self):
        self.log.info("Initializing metadata")
        funcs = idautils.Functions()
        for func in funcs:
            self.funcs.append(FuncMeta(func))

        self.log.info("Initalized metadata")

    def load_coverage(self, folder):
        self.log.info("Loading coverage information from %s", folder)
        files = os.listdir(folder)
        idx = 1
        for filename in files:
            self.log.info("Loading coverage %d/%d", idx, len(files))
            filepath = os.path.join(folder, filename)
            with open(filepath, "rb") as f:
                start_addr = struct.unpack("Q", f.read(8))[0]
                count_iter = struct.iter_unpack("H", f.read())
                off = 0
                for count in count_iter:
                    if count[0] > 0:
                        for func in self.funcs:
                            func.add_hits(start_addr + off, count[0])
                    off += 1
            idx += 1
