from typing import Callable, Tuple
from emmutaler.coverage.util import graph_size
from emmutaler.log import get_logger
import ida_graph
import ida_gdl
import idaapi

log = get_logger(__name__)

color_map = {
    0x8113e243: 0x00ff0000,
    0x8113e244: 0x0000ff00,
    0x8113e245: 0x000000ff,
}

class TikzWriter:
    def __init__(self, graph: ida_graph.mutable_graph_t, filename, width = 16.50764) -> None:
        self.graph = graph
        self.filename = filename
        self.width = width
        self.size = graph_size(self.graph)
        self.scale = width / float(self.size[0])
        self.height = self.size[1]*self.scale
        self.log = get_logger(__name__+".TikzWriter")

    def conv_point(self, p: ida_graph.point_t):
        x = float(p.x)
        y = float(p.y)
        # flip coords
        return (x*self.scale, self.height - y*self.scale)

    def conv_color(self, color: int):
        if color == 0xffffffff:
            color = 0x2d2d2d
        red = color & 0xff
        green = (color >> 8) & 0xff
        blue = (color >> 16) & 0xff
        return f"{{rgb,255:red,{red}; green,{green}; blue,{blue}}}"

    def write(self, addr, node_info: Callable[[int], Tuple[str, int]]):
        """Write the given graph at address addr as tikz to the filename.

        Parameters
        ----------
        addr : [type]
            [description]
        node_info : Callable[[int], Tuple[str, int]]
            Given an address of a node, optionally return better fitting contents and a color.
            Can return None for either to use default.
            Color is of form 0x00bbggrr
        """
        with open(self.filename, "w") as f:
            num_nodes = self.graph.size()
            func = idaapi.get_func(addr)
            flowchart = ida_gdl.qflow_chart_t("", func, idaapi.BADADDR, idaapi.BADADDR, 0)
            for i in range(num_nodes):
                # we only want visible nodes
                if not self.graph.is_visible_node(i):
                    continue
                
                rect: ida_graph.rect_t = self.graph.nrect(i)
                info = ida_graph.node_info_t()
                node: ida_gdl.qbasic_block_t = flowchart[i]
                ida_graph.get_node_info(info, self.graph.gid, i)
                # log.info("Node type: %s", type(node))
                info.ea = node.start_ea
                conts, color = node_info(info.ea)
                node_name = f"bb{info.ea:x}"
                height = rect.height()*self.scale
                if conts is None:
                    conts = ""
                if color is None:
                    color = info.bg_color
                # conts = ""
                if info.text != "":
                    log.info("Node has text: %s", info.text)
                    conts:str = info.text
                    # only keep first line!
                    conts = conts.splitlines()[0]
                # only show large enough nodes with text!
                if height < 0.2:
                    conts = ""
                x, y = self.conv_point(rect.center())
                f.write(f"\\node[fill={self.conv_color(color)}, minimum width={rect.width()*self.scale}cm, minimum height={height}cm, inner sep=0pt] ({node_name}) at ({x}cm, {y}cm) {{\\tiny {conts}}};\n")
                num_edges = self.graph.nsucc(i)
                for edgei in range(num_edges):
                    succ = self.graph.succ(i, edgei)
                    edge = ida_graph.edge_t(i, succ)
                    ei = self.graph.get_edge(edge)
                    edge_color = ei.color
                    if edge_color in color_map:
                        edge_color = color_map[edge_color]
                    src_point = ida_graph.point_t(rect.left, rect.bottom)
                    y_off = int(0.1 / self.scale)
                    # log.info("Edge color: %s, %s", type(ei.color), ei.color)
                    # src_point = rect.center()
                    # src_point.y += y_off
                    # src_point.x = rect.left
                    dst_rect = self.graph.nrect(succ)
                    dst_point = ida_graph.point_t(dst_rect.left, dst_rect.top)
                    # dst_point = dst_rect.center()
                    # dst_point.y -= y_off
                    # dst_point.x = dst_rect.left
                    src_point.x += ei.srcoff
                    dst_point.x += ei.dstoff
                    src_x, src_y = self.conv_point(src_point)
                    dst_x, dst_y = self.conv_point(dst_point)
                    edge_points: ida_graph.pointseq_t = ei.layout
                    f.write(f"\\draw[color={self.conv_color(edge_color)}]")
                    f.write(f"({src_x}cm, {src_y}cm) ")
                    for epi in range(edge_points.size()):
                        ep = edge_points.at(epi)
                        x, y = self.conv_point(ep)
                        f.write("--")
                        f.write(f" ({x}cm, {y}cm) ")
                    f.write("edge[->]")
                    f.write(f"({dst_x}cm, {dst_y}cm)")
                    f.write(";\n")
                f.write("\n\n")


