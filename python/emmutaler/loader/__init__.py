import os
import sys
from typing import Union
import idaapi
import ida_idaapi
import ida_loader
import ida_idp
import debugpy
from emmutaler.log import get_logger
log = get_logger(__name__)
from emmutaler.loader.og_stuff import post_process
from emmutaler.flatbuffers.VirtualSegment import VirtualSegment
from emmutaler.flatbuffers.LinkedSection import LinkedSection
from emmutaler.flatbuffers.LinkerMeta import LinkerMeta
from emmutaler.flatbuffers.BuildInfo import BuildInfo
from emmutaler.meta_file import load_meta

current_file = None

def create_segment(info: Union[VirtualSegment, LinkedSection], name, sclass):
    debugpy.breakpoint()
    segm = idaapi.segment_t()
    segm.bitness = 2 # 64-bit
    if isinstance(info, VirtualSegment) or "Size" in dir(info):
        segm.start_ea = info.Start()
        segm.end_ea = info.Start() + info.Size()
    else:
        segm.start_ea = info.Start()
        segm.end_ea = info.End()
    idaapi.add_segm_ex(segm, name, sclass, idaapi.ADDSEG_OR_DIE | idaapi.ADDSEG_SPARSE)

def load_file(fd: ida_idaapi.loader_input_t, neflags, format):
    global current_file
    log.info("Trying to load file %s", current_file)
    emmu_fname = current_file + ".emmu"
    if os.path.exists(emmu_fname):
        meta = load_meta(emmu_fname)
        build_info: BuildInfo = meta.BuildInfo()
        log.info("Loading SecureROM: %s", build_info.Tag())

        idaapi.set_processor_type("arm", ida_idp.SETPROC_LOADER_NON_FATAL)
        idaapi.get_inf_structure().lflags |= idaapi.LFLG_64BIT

        log.info("Adding segments")
        linker_info: LinkerMeta = meta.LinkerInfo()
        create_segment(linker_info.Text(), "TEXT", "CODE")
        create_segment(linker_info.Data(), "DATA", "DATA")
        create_segment(linker_info.Bss(), "BSS", "BSS")
        create_segment(linker_info.Stacks(), "STACK", "STACK")

        log.info("Loading file into segments...")
        text_start = linker_info.Text().Start()
        text_end = linker_info.DataRoStart()
        text_size = linker_info.TextSize()
        data_start = linker_info.Data().Start()
        data_end = linker_info.Data().End()
        fd.file2base(0, text_start, text_end, True)
        fd.seek(0)
        page_size = 0x3fff
        act_data_start = (text_size + page_size) & (~page_size)
        fd.file2base(act_data_start, data_start, data_end, True)

        log.info("Loaded file into segments, post processing...")
        post_process(text_start)

        return 1

    log.error("Could not find emmu file suddenly?: %s", emmu_fname)
    return 0

def accept_file(fd: ida_idaapi.loader_input_t, fname: str):
    global current_file
    log.info("Processing file %s", fname)
    emmu_fname = fname + ".emmu"
    if os.path.exists(emmu_fname):
        current_file = fname
        log.info("File has emmu info, can load!")
        return {"format" : "SecureROM (AArch64)", "processor" : "arm", "options" : ida_loader.ACCEPT_FIRST | 1 }
    return 0