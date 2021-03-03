.section .text
.global rom_start_trampoline
rom_start_trampoline:
    /* Since the bootrom doesn't know that we execute before it,
      it will not save the link & frame regs on entry.
      Hence we do this here, so that we can get full backtrace information. */
    stp x29, x30, [sp, #-0x10]!
    mov x29, sp
    /* Second fake function frame, otherwise unwind is confused. */
    mov x0, 0x0
    movk x0, 0x1, lsl 32
    stp x29, x0, [sp, #-0x10]!
    br x0


.section .rom.text, "ax"
.global fake_rom_start
fake_rom_start:
stp x29, x30, [sp, #-0x10]!
mov x29, sp
mov x0, 0x10
movk x0, 0x1, lsl 32
stp x29, x0, [sp, #-0x10]!
mov x29, sp
.global rom_start
.type rom_start,@function
rom_start:
.incbin "build/rom.text", 0, 0x6cc0
.global platform_start
.type platform_start, @function
platform_start:
.incbin "build/rom.text", 0x6cc0



.section .rom.data, "aw"
.incbin "build/rom.data"
