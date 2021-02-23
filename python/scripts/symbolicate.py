import idaapi
from emmutaler.log import get_logger
log = get_logger(__name__)

log.info("Running script!")
idaapi.qexit(0)