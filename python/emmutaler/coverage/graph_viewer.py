from logging import getLogger
from typing import List, Tuple, Union
from emmutaler.coverage.util import graph_size
from emmutaler.log import get_logger
import idaapi
import ida_kernwin
import ida_funcs
import ida_range
import ida_graph
from ida_kernwin import PluginForm
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
# from PyQt5 import Qt
import time

def qwidget(twidget) -> QWidget:
    """Converts the given IDA twidget to a QWidget

    Parameters
    ----------
    twidget : [type]
        [description]

    Returns
    -------
    QWidget
        [description]
    """
    return PluginForm.TWidgetToPyQtWidget(twidget)

def get_func_rangevec(fn: Union[idaapi.func_t, int]) -> idaapi.rangevec_t:
    res = idaapi.rangevec_t()
    func = fn
    if not isinstance(fn, idaapi.func_t):
        func = idaapi.get_func(fn)
    rs = idaapi.rangeset_t()
    ret = idaapi.get_func_ranges(rs, func)
    if ret == idaapi.BADADDR:
        return res
    for i in range(rs.nranges()):
        res.push_back(rs.getrange(i))
    return res

class GraphViewer:
    def __init__(self, addr, name = "GraphViewer") -> None:
        self.addr = addr
        self.func: idaapi.func_t = idaapi.get_func(self.addr)
        self.log = get_logger(__name__ + ".GraphViewer")
        self.log.info("Found func %s at 0x%x", idaapi.get_name(self.func.start_ea), self.func.start_ea)
        self.wname = name
        self._qgraph_widget = None
        self._qgraph_viewer = None
        self.graph : ida_graph.mutable_graph_t = None
    
    @property
    def wact_name(self) -> str:
        return f"IDA View-{self.wname}"

    @property
    def qgraph_widget(self) -> QWidget:
        if self._qgraph_widget is None:
            self._qgraph_widget = qwidget(self.graph_widget)
        return self._qgraph_widget

    @property
    def qgraph_viewer(self) -> QWidget:
        if self._qgraph_viewer is None:
            self._qgraph_viewer = qwidget(self.graph_viewer).children()[0]
        return self._qgraph_viewer

    @property
    def window(self):
        return self.qgraph_widget.window()

    def open(self):
        rv = get_func_rangevec(self.func)
        self.graph_widget = ida_kernwin.open_disasm_window(self.wname, rv)
        self.graph_viewer = ida_graph.get_graph_viewer(self.graph_widget)
        self.graph = ida_graph.get_viewer_graph(self.graph_viewer)
        # time.sleep(1)

    def close(self):
        ida_kernwin.close_widget(self.graph_widget, 0)

    def grab(self) -> QPixmap:
        return self.qgraph_viewer.grab()

    def wait(self, t = 2):
        steps = 2
        for i in range(steps):
            time.sleep(float(t) / steps)

    def resize(self, width, height):
        window_size: QSize = self.window.size()
        viewer_size: QSize = self.qgraph_viewer.size()
        diff = (window_size.width() - viewer_size.width(), window_size.height() - viewer_size.height())
        self.log.info("diff: %d x %d", diff[0], diff[1])
        act_new_size = (diff[0] + width, diff[1] + height)
        self.window.resize(act_new_size[0], act_new_size[1])

    def screenshot(self, scale = 1, width = 1024, padding = 40) -> QPixmap:
        # undock
        ida_kernwin.set_dock_pos(self.wact_name, "", ida_kernwin.DP_FLOATING, 0, 0, 0, 0)
        self.qgraph_widget.setStyleSheet("CustomIDAMemo {qproperty-graph-bg-top              : #ffffff !important; qproperty-graph-bg-bottom           : #ffffff !important; background-color: rgba(0, 0, 0, 0);} background-color: rgba(0, 0, 0, 0);")
        self.qgraph_viewer.setStyleSheet("CustomIDAMemo {qproperty-graph-bg-top              : #ffffff !important; qproperty-graph-bg-bottom           : #ffffff !important; background-color: rgba(0, 0, 0, 0);} background-color: rgba(0, 0, 0, 0);")
        self.window.setStyleSheet("background-color: rgba(0, 0, 0, 0);")
        self.qgraph_widget.setAttribute(Qt.WA_NoSystemBackground)
        self.qgraph_widget.setAttribute(Qt.WA_TranslucentBackground)
        self.qgraph_widget.resize(1024, 1024)
        gw, gh = graph_size(self.graph)
        tw, th = gw, gh
        if width is None:
            tw *= scale
            th *= scale
        else:
            tw = width
            scale = tw / gw
            th *= scale
        tw += 2*padding
        th += 2*padding
        tw = int(tw)
        th = int(th)
        self.log.info("Resizing %d -> %d, %d -> %d", gw, int(tw), gh, int(th))
        # ida_kernwin.info("Hello")
        self.resize(int(tw), int(th))
        self.qgraph_viewer.setGeometry(0, 0, tw, th)
        self.qgraph_widget.setGeometry(0, 0, tw, th)
        self.qgraph_widget.parentWidget().setGeometry(0, 0, tw, th)
        loc = idaapi.graph_location_info_t()
        loc.zoom = scale
        loc.orgx = -padding / scale
        loc.orgy = -padding / scale
        ida_graph.viewer_set_gli(self.graph_viewer, loc)
        # ida_kernwin.info("Hello")
        # self.wait()
        # time.sleep(1)
        # ida_graph.viewer_fit_window(self.graph_viewer)
        # time.sleep(1)
        # idaapi.auto_wait()
        # self.wait()
        # ida_kernwin.info("Hello")
        # p = QPixmap(tw, th)
        # self.qgraph_viewer.render(p, QPoint(), QRegion(0, 0, tw, th))
        return self.grab()

def screenshot_graph(addr, filename, scale = 1, width = 2048) -> QPixmap:
    viewer = GraphViewer(addr)
    viewer.open()
    p = viewer.screenshot(scale, width)
    p.save(filename)
    # viewer.log.info("Not closing!")
    viewer.close()
    return viewer

log = getLogger(__name__)

if __name__ == "__main__":
    log.info("Screenshotting!")
    screenshot_graph(idaapi.get_screen_ea(), "/Users/leonardogalli/Code/ETH/thesis/results/test.png")