from collections import OrderedDict
import re
import os
import sys

def_re = re.compile(r"^#define\s+(?P<name>\w+)\s+(?P<value>\(.*\))$", re.IGNORECASE | re.MULTILINE)

defs = """
#define kSecurityModeExUntrust			(1 << 4)
#define kSecurityModeKDPEnabled			(1 << 5)
#define kSecurityModeDebugCmd			(1 << 8)
#define kSecurityModeMemAccess			(1 << 16)
#define kSecurityModeHWAccess			(1 << 17)
#define kSecurityModeGIDKeyAccess		(1 << 18)
#define kSecurityModeUIDKeyAccess		(1 << 19)
#define kSecurityModeDevCertAccess		(1 << 20)
#define kSecurityModeProdCertAccess		(1 << 21)
#define kSecurityOptionClearProduction		(1 << 24)
#define kSecurityOptionMixNMatchPrevented	(1 << 25)
#define kSecurityOptionBootManifestHashValid	(1 << 26)
#define kSecurityOptionLockFuses		(1 << 27)
#define kSecurityStatusSecureBoot		(1 << 28)
#define kSecurityStatusSystemTrusted		(1 << 29)
"""

enum_vals = OrderedDict()

for match in def_re.finditer(defs):
    name = match.group("name")
    val = match.group("value")
    act_val = eval(val)
    enum_vals[name] = act_val

print(f"enum security_mode {{")
for name, val in enum_vals.items():
    print(f"\t{name} = 0x{val:x},")
print(f"}}")