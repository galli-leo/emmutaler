import os
import debugpy
from emmutaler.log import get_logger
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

# install()

def load_file(fd, neflags, format):
    from emmutaler.loader import load_file
    return load_file(fd, neflags, format)

def accept_file(fd, fname):
    from emmutaler.loader import accept_file
    return accept_file(fd, fname)