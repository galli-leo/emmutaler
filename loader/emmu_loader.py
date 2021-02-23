import os
import debugpy
import ida_loader
from emmu_loader.log import log
from emmu_loader.Emmutaler.ROMMeta import *
from emmu_loader.Emmutaler.BuildInfo import *
import threading
from threading import current_thread

threadLocal = threading.local()

script_folder = "/Users/leonardogalli/Code/ETH/thesis/emmutaler/loader/"
getcwd_original = os.getcwd

def getcwd_hook():
    global script_folder

    cwd = getcwd_original()
    if cwd.lower() in script_folder.lower() and script_folder.lower() != cwd.lower():
        cwd = script_folder
    return cwd

def set_script_folder(folder):
    global script_folder

    script_folder = folder

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

# install()

def load_file(fd, neflags, format):
    from emmu_loader import load_file
    return load_file(fd, neflags, format)

def accept_file(fd, fname):
    from emmu_loader import accept_file
    return accept_file(fd, fname)