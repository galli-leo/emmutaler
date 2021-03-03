#include <stdio.h>
#include "rom.h"
#include <unistd.h>
#include <stdlib.h>
#include "debug/signals.h"

void sub2_function()
{
    int local1 = 123;
    printf("Entered sub2_function... %d\n", local1);
    void* illegal_access = 0x2000000000;
    *(uint64_t*)illegal_access = 0x0;
}

void sub_function()
{
    int local2 = 123;
    printf("Entered sub_function... %d\n", local2);
    sub2_function();
}

int main() {
    install_signal_handler();

    printf("Hello World! ROM LOADED AT: %p, %p\n", &rom_start, &rom_platform_start);
    // sub_function();
    fake_rom_start();
    rom_platform_start();
    printf("Goodbye!\n");
    return 0;
}