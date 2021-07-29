from collections import OrderedDict
import threading
from typing import Callable, List, Tuple
import idaapi
from emmutaler.log import get_logger
from emmutaler.fbs.Symbol import Symbol, SymbolT
from emmutaler.fbs.MetaState import MetaState
from emmutaler.util import get_plugin_args
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

RUNS = ["usb", "img", "img_oob"]
FUNCS = ["usb_core_handle_usb_control_receive", "usb_core_event_handler", "usb_dfu_handle_interface_request", "image4_load", "image4_validate_property_callback_interposer"]
BINS = [0.0, 0.5 / 100, 2.0 / 100, 10.0 / 100, 25.0 / 100, 1]
num_colors = len(BINS) - 1

TBL_ENTRIES = {
    "USB": ["usb_core_handle_usb_control_receive", "usb_core_event_handler", "usb_dfu_handle_interface_request", "usb_dfu_data_received"],
    "IMG4": ["image4_load", "image4_validate_property_callback_interposer", "_image4_get_partial", "Img4DecodePerformTrustEvaluatation"],
    "Certificates": ["parse_chain", "verify_parse_chain", "verify_payload_properties"],
    "DER": ["DERDecodeItemPartialBuffer", "DERParseSequenceContent", "_DERParseInteger64"]
}

def get_color_idx(percentage):
    color_idx = 0
    for i in range(num_colors+1):
        if BINS[i] > percentage:
            break
        color_idx = i
    return color_idx

def refreshed():
    log.info("Database is refreshed!")

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

def latexify_name(name):
    return name.replace('_', '\\_')
tbl_cols: List[Tuple[str, Callable[[FunctionMetadata, FunctionCoverage], str]]] = [
    ("Function", lambda m, c: f"\\footnotesize \\texttt{{{latexify_name(m.name)}}}"),
    ("Coverage", lambda m, c: f"${c.instruction_percent*100:.2f}\%$"),
    ("BB Hit", lambda m, c: f"{c.nodes_executed} \\/ {m.node_count}"),
    ("Instr Hit", lambda m, c: f"{c.instructions_executed} \\/ {m.instruction_count}"),
    ("Size", lambda m, c: f"{m.size} B"),
    ("Cyclomatic Complexity", lambda m, c: f"{m.cyclomatic_complexity}")
]
TABLE_COLS = OrderedDict(tbl_cols)

def get_table_rows(span_name, ctx: LighthouseContext):
    funcs = TBL_ENTRIES[span_name]
    text_color = "white"
    out = ""
    num_rows = len(funcs)
    count = 0
    act_funcs = []
    for func in funcs:
        addr = idaapi.get_name_ea(0, func)
        if addr == idaapi.BADADDR:
            log.error("Failed to retrieve address for function %s", func)
            continue
        function_metadata = ctx.metadata.functions[addr]
        function_coverage: FunctionCoverage = ctx.director.coverage.functions.get(addr, None)
        if function_coverage is None:
            log.error("Could not retrieve coverage for function %s", func)
            continue
        act_funcs.append(func)
    for idx, func in enumerate(act_funcs):
        addr = idaapi.get_name_ea(0, func)
        if addr == idaapi.BADADDR:
            log.error("Failed to retrieve address for function %s", func)
            continue
        function_metadata = ctx.metadata.functions[addr]
        function_coverage: FunctionCoverage = ctx.director.coverage.functions.get(addr, None)
        if function_coverage is None:
            log.error("Could not retrieve coverage for function %s", func)
            continue
        percentage = function_coverage.instruction_percent
        color = get_color_idx(percentage)
        span = f"\\rowcolor{{ccvg{color}}} "
        count += 1
        if idx == len(act_funcs) - 1:
            #\\color{{{text_color}}}
            span += f"\\multirow{{-{count}}}{{*}}{{{span_name}}}"
        cols = [span]
        for _, mapper in TABLE_COLS.items():
            txt = mapper(function_metadata, function_coverage)
            # cols.append(f"\\color{{{text_color}}}{txt}")
            cols.append(txt)
        row = " & ".join(cols)
        row += "\\\\\n"
        out += row
    return out
        
def write_table_items(output, prefix, ctx: LighthouseContext):
    log.info("Writing table to %s", output)
    os.makedirs(output, exist_ok=True)
    for span in TBL_ENTRIES.keys():
        output_file = os.path.join(output, f"{span.lower()}.tex")
        with open(output_file, "w") as f:
            f.write(get_table_rows(span, ctx))

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
    output_dir = args[2]

    
    colors = []
    log.info("Writing coverage colors")
    color_file = os.path.join(output_dir, "cvg_colors.tex")
    color_tbl_file = os.path.join(output_dir, "cvg_colors_tbl.tex")
    with open(color_file, "w") as f:
        palette = ctx.painter.palette
        with open(color_tbl_file, "w") as tbl_f:
            for i in range(num_colors+1):
                if i+1 < len(BINS):
                    perc = BINS[i+1]
                else:
                    perc = 1.0
                prev_perc = BINS[i]
                color_perc = float(i) / num_colors
                color: QColor = compute_color_on_gradiant(
                    color_perc,
                    palette.table_coverage_bad,
                    palette.table_coverage_good
                )
                f.write(f"\\definecolor{{ccvg{i}}}{{RGB}}{{{color.red()},{color.green()},{color.blue()}}}\n")
                span = ""
                lhs_bracket = "["
                if i == 0:
                    lhs_bracket = "("
                    span = f"\\multirow{{{num_colors}}}{{*}}{{Covered}}"
                if i < num_colors:
                    tbl_f.write(f"{span} & ${lhs_bracket}{prev_perc*100:.1f}\%, {perc*100:.1f}\%)$ & \\cellcolor{{ccvg{i}}} \\\\ \n")
                else:
                    tbl_f.write(f"& $100.0\%$ & \\cellcolor{{ccvg{i}}} \\\\\n")
                colors.append(color.red() | (color.green() << 8) | (color.blue() << 16))
    names = {}
    for run in RUNS:
        usb_dir = os.path.join(input_dir, run)
        add_names = create_batches.load_aggr_cov(usb_dir, run)
        names[run] = add_names
    idaapi.auto_wait()
    for run, run_names in names.items():
        log.info("Creating coverage graphs and tables for run %s", run)
        run_dir = os.path.join(output_dir, run)
        os.makedirs(run_dir, exist_ok=True)
        for name in run_names:
            log.info("Creating coverage graphs and tables for %s", name)
            try:
                ctx.director.select_coverage(name)
            except Exception:
                log.warning("Could not load coverage for %s", name)
                continue
            log.info("Waiting for painting to complete")
            # ctx.painter._action_complete.wait()
            batch_dir = os.path.join(run_dir, name)
            os.makedirs(batch_dir, exist_ok=True)
            graphs_dir = os.path.join(batch_dir, "graphs")
            os.makedirs(graphs_dir, exist_ok=True)
            tables_dir = os.path.join(batch_dir, "tables")
            write_table_items(tables_dir, "", ctx)
            for fname in FUNCS:
                log.info("Creating picture for %s:%s", name, fname)
                faddr = idaapi.get_name_ea(0, fname)
                
                event = ctx.painter.force_clear()
                wait_event(event)
                event = ctx.painter.repaint()
                wait_event(event)
                # ctx.painter._priority_paint_functions(faddr)
                log.info("Function %s is at 0x%x", fname, faddr)
                screen_name = os.path.join(graphs_dir, f"{name}_{fname}.png")
                tikz_name = os.path.join(graphs_dir, f"{name}_{fname}.tex")
                viewer = graph_viewer.GraphViewer(faddr)
                viewer.open()
                writer = write_tikz.TikzWriter(viewer.graph, tikz_name)

                def node_info(node_addr):
                    log.debug("Calculating percentage for addr: 0x%x", node_addr)
                    db_coverage = ctx.director.coverage
                    db_metadata = ctx.director.metadata
                    node_coverage = db_coverage.nodes.get(node_addr, None)
                    if node_coverage is None:
                        log.debug("Failed to find node_coverage")
                        return (None, None)
                    functions = db_metadata.get_functions_by_node(node_addr)

                    for function in functions:
                        # attempt to safely fetch the node metadata from a function
                        node_metadata = function.nodes.get(node_addr, None)
                        func_coverage = db_coverage.functions[function.address]

                        #
                        # this is possible if function is getting torn down. this is because
                        # we don't use locks. this just means it is time for us to bail as
                        # the metadata state is changing and the paint should be canceled
                        #

                        if not node_metadata:
                            node_metadatas = []
                            break

                        # logger.info("Function 0x%x has %d max executions", function.address, func_coverage.max_executions)
                        
                        percentage = float(node_coverage.executions) / func_coverage.max_executions
                        conts = f"${percentage*100:.2f}\\%$"
                        color_idx = 0
                        for i in range(num_colors+1):
                            if BINS[i] > percentage:
                                break
                            color_idx = i
                        # color_idx = int(percentage*num_colors)
                        if percentage == 0.0:
                            return (None, None)
                        return (conts, colors[color_idx])
                    return (None, None)

                writer.write(faddr, node_info)
                viewer.close()
                # graph_viewer.screenshot_graph(faddr, screen_name)



except:
    log.exception("Failed to load coverage!", exc_info=True)
    idaapi.qexit(1)

log.info("done here, exiting")
idaapi.qexit(0)