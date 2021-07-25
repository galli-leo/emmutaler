from typing import List
from emmutaler.log import get_logger
import ida_range
import ida_funcs
import ida_graph
import ida_bytes
import ida_name
import ida_gdl
import idaapi

class BaseMeta:
    def __init__(self):
        self.ranges = ida_range.rangeset_t()
        self.instructions = {}
        self.instr_hitmap = {}
        self.setup()

    def setup(self):
        """General setup stuff, that should be called, after subclass initializes itself and fills e.g. instructions
        """
        for addr in self.instructions:
            self.instr_hitmap[addr] = 0

    @property
    def num_instr(self):
        return len(self.instructions)

    def add_hits(self, addr, count):
        """Add the hit count at address to the internal hitmap.
        Can be implemented by subclass

        Parameters
        ----------
        addr : ea_t
            location of hit instruction
        count : int
            num
        """
        if self.ranges.contains(addr):
            if addr not in self.instr_hitmap:
                # shouldn't actually be hit!
                self.instr_hitmap[addr] = 0
            self.instr_hitmap[addr] += count

    def initialize(self):
        """Here subclass should initialize e.g. instructions and call setup afterwards
        """
        self.setup()


class BlockMeta(BaseMeta):
    def __init__(self, start, end, node_id, bb: ida_gdl.BasicBlock, graph: ida_gdl.qflow_chart_t, func: ida_funcs.func_t):
        self.start = start
        self.end = end
        self.node_id = node_id
        self.bb = bb
        self.graph = graph
        self.func = func
        self.edge_out = idaapi.BADADDR
        super().__init__()

    def initialize(self):
        current_address = self.start
        node_end = self.end

        self.ranges.add(self.start, self.end)

        #
        # loop through the node's entire address range and count its
        # instructions. Note that we are assuming that every defined
        # 'head' (in IDA) is an instruction
        #

        while current_address < node_end:
            instruction_size = ida_bytes.get_item_end(current_address) - current_address
            self.instructions[current_address] = instruction_size
            current_address += instruction_size

        self.edge_out = current_address - instruction_size

        return super().initialize()

class FuncMeta(BaseMeta):
    def __init__(self, addr):
        self.addr = addr
        self.func: ida_funcs.func_t = None
        self.graph: ida_gdl.qflow_chart_t = None
        self.nodes: List[BlockMeta] = []
        self.name = "unknown"
        super().__init__()

    def initialize(self):
        self.func = ida_funcs.get_func(self.addr)
        self.name = ida_name.get_name(self.addr)
        self.graph = ida_gdl.qflow_chart_t("", self.func, idaapi.BADADDR, idaapi.BADADDR, 0)

        for node_id in range(self.graph.size()):
            node: ida_gdl.BasicBlock = self.graph[node_id]

            #
            # the node current node appears to have a size of zero. This means
            # that another flowchart / function owns this node so we can just
            # ignore it...
            #

            if node.start_ea == node.end_ea:
                continue

            # create a new metadata object for this node
            node_metadata = BlockMeta(node.start_ea, node.end_ea, node_id, node, self.graph, self.func)

            #
            # establish a relationship between this node (basic block) and
            # this function metadata (its parent)
            #

            self.nodes.append(node_metadata)
            self.instructions.update(node_metadata.instructions)
            self.ranges.add(node_metadata.ranges)

        return super().initialize()

    def add_hits(self, addr, count):
        # early exit if not contained
        if not self.ranges.contains(addr):
            return
        for node in self.nodes:
            node.add_hits(addr, count)
        return super().add_hits(addr, count)