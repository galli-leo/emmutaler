from emmutaler.fbs.ROMMeta import ROMMeta, ROMMetaT
from emmutaler.log import get_logger
import flatbuffers
log = get_logger(__name__)

def load_meta(fname) -> ROMMeta:
    buf = open(fname, 'rb').read()
    buf = bytearray(buf)
    try:
        return ROMMeta.GetRootAsROMMeta(buf, 0)
    except:
        log.exception("Failed to parse flatbuffer from input file %s", fname)
    return None

def load_meta_t(fname) -> ROMMetaT:
    meta = load_meta(fname)
    return ROMMetaT.InitFromObj(meta)

def save_meta(fname, meta: ROMMetaT):
    builder = flatbuffers.Builder(1024)
    fin = meta.Pack(builder)
    builder.Finish(fin)
    buf = builder.Output()
    with open(fname, 'wb') as f:
        f.write(buf)