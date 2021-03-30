#include <stdint.h>
#include <stdio.h>

void vbar_el1_handler(uint64_t addr)
{
    printf("Handling vbar_el1_here, exception vector base is %p\n", addr);
}

void arch_cpu_init_handler()
{
    printf("Pretending to do arch_cpu_init here...\n");
}