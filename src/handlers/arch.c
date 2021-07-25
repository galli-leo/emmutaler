#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

void vbar_el1_handler(uint64_t addr)
{
    printf("Handling vbar_el1_here, exception vector base is %p\n", addr);
}

void arch_cpu_init_handler()
{
    printf("Pretending to do arch_cpu_init here...\n");
}

// Totally secure entropy source!
// TODO: Make sure this doesn't affect fuzzing!
uint32_t platform_get_entropy()
{
    return 0x4;
}

int platform_get_sep_nonce(uint8_t* buf)
{

    strcpy(buf, "RANDOM_NONCE");
    return 0;
}

uint64_t timer_get_ticks()
{
    uint64_t clock_val = clock();
    double seconds = clock_val / (double)CLOCKS_PER_SEC;
    // in rom: 24 ticks per musecond
    return (uint64_t)((seconds / (1000 * 1000)) * 24.0 );
}