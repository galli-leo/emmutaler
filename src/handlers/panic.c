#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>

void panic_handler()
{
    printf("panic called, lets just exit for now\n");
    exit(69);
}

void heap_panic_handler()
{
    printf("heap_panic called, this is bad (for apple)\n");
    assert(false);
}