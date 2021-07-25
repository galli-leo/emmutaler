#include "debug/signals.h"
#include "debug/log.h"

void report_no_boot_image_handler(uint32_t result)
{
    some_kind_of_report_handler(result, 0, 0, 0);
}

void some_kind_of_report_handler(uint32_t result, int a2, int a3, int a4)
{
#if DEBUG
    log_debug("report_handler(0x%08x, 0x%x, 0x%x, 0x%x)", result, a2, a3, a4);
    void* prev_pc = __builtin_return_address(0);
    void* fp = __builtin_frame_address(0);
    // printf("STACKTRACE:\n");
    // print_stacktrace(prev_pc, fp);
#endif
}