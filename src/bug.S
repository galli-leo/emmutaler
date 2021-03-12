.global dini_muetter
dini_muetter:
stp x29, x30, [sp, #-0x10]!
mov x29, sp
bl buggy
ret

.global buggy
buggy:
    br x0
    blraaz x0