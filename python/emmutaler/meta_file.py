from emmutaler.flatbuffers.ROMMeta import ROMMeta
from emmutaler.log import get_logger
log = get_logger(__name__)

def load_meta(fname) -> ROMMeta:
    buf = open(fname, 'rb').read()
    buf = bytearray(buf)
    try:
        return ROMMeta.GetRootAsROMMeta(buf, 0)
    except:
        log.exception("Failed to parse flatbuffer from input file %s", fname)
    return None