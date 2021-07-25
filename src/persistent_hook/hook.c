#include "../../../../AFLplusplus/qemu_mode/qemuafl/qemuafl/api.h"

#include <stdio.h>
#include <string.h>

// #define IMG_BASE (0x320069000)
// #define IMG_MAX 0x10000

void afl_persistent_hook(struct arm64_regs *regs, uint64_t guest_base,
                         uint8_t *input_buf, uint32_t input_buf_len) {
\
#define g2h(x) ((void *)((unsigned long)(x) + guest_base))
#define h2g(x) ((uint64_t)(x)-guest_base)

  // In this example the register RDI is pointing to the memory location
  // of the target buffer, and the length of the input is in RSI.
  // This can be seen with a debugger, e.g. gdb (and "disass main")
#if DEBUG
  printf("Placing input into 0x%lx, sized 0x%x\n", IMG_BASE, input_buf_len);
#endif
  // printf("RETURN ADDR: 0x%llx\n", regs->lr);
  // uint64_t* regs_ptr = &regs->x0;
  // for (int i = 0; i < 31; i++) {
  //   printf("X%02d: %016llx ", i, regs_ptr[i]);
  // }
  // printf("SP: %016x GB: %016x", regs->sp, guest_base);
  // printf("\n");

  uint64_t max_buf = regs->x1;
  if (input_buf_len > max_buf) input_buf_len = max_buf;

  // if (input_buf_len > IMG_MAX) input_buf_len = IMG_MAX;
  memcpy(g2h(regs->x0), input_buf, input_buf_len);

  // for (int i = -0x100 / 8; i <= 0x100 / 8; i += 0x10 / 8) {
  //   printf("sp+%02x: %016x  %016x\n", i*8, stack_ptr[i], stack_ptr[i+1]);
  // }

#undef g2h
#undef h2g

}

int afl_persistent_hook_init(void) {

  // 1 for shared memory input (faster), 0 for normal input (you have to use
  // read(), input_buf will be NULL)
  return 1;

}