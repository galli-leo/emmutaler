from importlib import reload
import emmutaler.mib
import emmutaler
reload(emmutaler.mib)
reload(emmutaler)
from emmutaler.mib import MibHandler

handler = MibHandler()
handler.load_by_name()
handler.comment_usages()