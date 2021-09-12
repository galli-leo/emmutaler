from collections import OrderedDict
import threading
from typing import Callable, List, Tuple
import idaapi
import idautils
from emmutaler.log import get_logger
from emmutaler.fbs.Symbol import Symbol, SymbolT
from emmutaler.fbs.MetaState import MetaState
from emmutaler.util import func_str, get_func, get_plugin_args, log_list
from emmutaler.typeinf import GenHeader, print_item_type
from emmutaler.coverage import create_batches, graph_viewer, write_tikz
from lighthouse import get_context
from lighthouse.context import LighthouseContext
from lighthouse.util import is_mainthread
from lighthouse.util.qt.shim import QT_AVAILABLE
from lighthouse.util.qt import flush_qt_events
from lighthouse.metadata import FunctionMetadata
from lighthouse.coverage import FunctionCoverage
import os
import debugpy
from emmutaler.log import get_logger
from lighthouse.util.qt.util import compute_color_on_gradiant
from PyQt5.QtGui import QColor
from emmutaler.reachable import get_reachable, Reachability

log = get_logger(__name__)

def install():
    # os.getcwd = getcwd_hook
    import traceback
    try:
        import debugpy
        # debugpy.log_to("/Users/leonardogalli/Code/ETH/thesis/emmutaler/logs")
        debugpy.configure(python="/usr/local/bin/python3")
        # 5678 is the default attach port in the VS Code debug configurations. Unless a host and port are specified, host defaults to 127.0.0.1
        debugpy.listen(("0.0.0.0", 5678))
        log.info("Waiting for debugger attach")
        debugpy.wait_for_client()
        debugpy.breakpoint()
    except Exception as e:
        pass

RUNS = [
    "usb",
    "img", "img_small", "img_oob"
]

COLORS = [
0xDB133C,
0x800104,
0x2F2B4A,
0x54518C,
0x9490FC,
0x2B6F51,
0x47B685,
]

def get_color(idx):
    val = COLORS[idx]
    return QColor(val)

def get_color_idx(percentage):
    color_idx = 0
    for i in range(num_colors+1):
        if BINS[i] > percentage:
            break
        color_idx = i
    return color_idx

def refreshed():
    log.debug("Database is refreshed!")

def wait_event(event: threading.Event, interval = 0.02):
    interval = 0.02    # the interval which we wait for a response
    if is_mainthread():
        log.debug("We are on main thread, so flushing qt events")
    else:
        log.warning("We are not actually on main thread???")
    # run until the message arrives through the future (a queue)
    while True:

        # block for a brief period to see if the future completes
        if event.wait(interval):
            return

        #
        # if we are executing (well, blocking) as the main thread, we need
        # to flush the event loop so IDA does not hang
        #

        if QT_AVAILABLE and is_mainthread():
            flush_qt_events()

# install()
try:
    # Don't save anything we do here!
    idaapi.process_config_directive("ABANDON_DATABASE=YES")
    idaapi.auto_wait()
    ctx: LighthouseContext = get_context(None)
    # ctx.director.refreshed(refreshed)
    ctx.director.metadata.abort_refresh(True)
    log.info("Forcing refresh of lighthouse director, hopefully this fixes stuff!")
    ctx.director.refresh()
    idaapi.auto_wait()
    args = get_plugin_args()
    log.info("Args: %s", args)
    input_dir = args[1]
    names = {"aggr": ["Aggregate"]}
    for run in RUNS:
        usb_dir = os.path.join(input_dir, run)
        add_names = create_batches.load_fuzzing_cov(usb_dir, run)
        names[run] = add_names
    called_fns = ["usb_core_event_handler", "init_entropy_source", "getDFUImage", "security_protect_memory", "usb_core_handle_usb_control_receive", "usb_core_complete_endpoint_io", "image_load"]
    # DECRYPT IMG4
    # DECOMPRESS IMG4
    nono_bbs = [0x100005E80, 0x100006104]
    # add patched fns start bbs
    patched_fns = ["report_no_boot_image", "some_kind_of_report", "synopsys_otg_controller_init", "platform_get_entropy", "platform_get_sep_nonce", "_aes_crypto_cmd"]
    for fn in patched_fns:
        fn_ea = idaapi.get_name_ea(idaapi.BADADDR, fn)
        nono_bbs.append(fn_ea)
    r = Reachability(nono_bbs)
    r.add_panic_fn("_panic")
    for fn in called_fns:
        r.run(fn)
    try:
        ctx.director.select_coverage("Aggregate")
    except Exception:
        log.error("Could not load coverage for Aggregate")
    db_cov = ctx.director.coverage
    hitmap = db_cov.data
    total = len(r.reachable)
    log.info("Total reachable: %d", total)
    covered = 0
    for addr in r.reachable:
        if addr in hitmap and hitmap[addr] > 0:
            covered += 1
        # else:
        #     log.info("Not covered: 0x%x", addr)
    log.info("Total coverage percent of all reachable instructions is %.2f %%", float(covered) / total * 100)
    reach_list = []
    for (func, path) in r.fns_reached.values():
        path_txt = "\n"
        for item in path:
            path_txt += "\t"*3 + item + "\n"
        reach_list.append(f"{func_str(func)}: {path_txt}")
    # log.info("List of reachable functions: %s", log_list([func_str(f) for f in r.fns.values()]))
    log.info("List of reachable function: %s", log_list(reach_list))
    panic_fns = []
    for key, val in r.panic_fns.items():
        if val:
            panic_fns.append(func_str(get_func(key)))
    log.info("List of panic functions: %s", log_list(panic_fns))

except:
    log.exception("Failed to load coverage!", exc_info=True)
    idaapi.qexit(1)

log.info("done here, exiting")
# idaapi.qexit(0)