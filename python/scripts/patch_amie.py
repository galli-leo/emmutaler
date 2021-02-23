import os
import sys
curr_path = os.path.dirname(__file__)
parent = os.path.dirname(curr_path)
sys.path.append(parent)
from emmutaler.sysregs import *
from emmutaler.log import get_logger
import json
log = get_logger(__name__)

OLD_REGNAME = "S3_<op1>_<Cn>_<Cm>_<op2>"

def gen_sys_regs():
    ret = {}
    for reg, info in SYSREGS.items():
        ops = parse_sys_reg(reg)
        name = info[0]
        ret[name] = ops

    return ret

def gen_sys_regs_desc():
    ret = {}
    for reg, info in SYSREGS.items():
        name, desc = info
        ret[name] = {
            "long_name": "TODO",
            "purpose": f"{desc} ({reg})"
        }
    return ret

PATCH_VER_KEY = "__patched_version"
PATCH_VER = "0.0.1"

def do_patch():
    log.info("Patching AMIE to include Apple system registers")
    ida_path = os.getenv("IDA_PATH")
    amie_meta = os.path.join(ida_path, "plugins", "aarch64.json")
    log.info("Patching json: %s", amie_meta)
    data = json.load(open(amie_meta))
    if not PATCH_VER_KEY in data or data[PATCH_VER_KEY] != PATCH_VER:
        log.info("Not yet patched, patching!")
        encodings: dict = data["registers"]["encodings"]["MSR|MRS"]
        encodings.update(gen_sys_regs())
        del encodings[OLD_REGNAME]
        regs: dict = data["registers"]["registers"]
        regs.update(gen_sys_regs_desc())
        data[PATCH_VER_KEY] = PATCH_VER

        log.info("Done patching, writing to %s", amie_meta)
        with open(amie_meta, "w") as f:
            json.dump(data, f, indent=2, sort_keys=True)


if __name__ == "__main__":
    do_patch()