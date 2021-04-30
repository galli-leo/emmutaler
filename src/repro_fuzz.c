#include <stdio.h>
#include <stdint.h>

int do_fuzz(void* address, uint64_t img_size, uint64_t another_one)
{
    printf("Arguments: %p, 0x%llx, 0x%llx\n", address, img_size, another_one);
    printf("Arguments (%d), but again: %p, 0x%llx, 0x%llx\n", 0xff, address, img_size, another_one);
    return 0;
}

int main() {
    do_fuzz(1, 1, 1);
    // do_fuzz(1, 1, 1);
    // for (int i = 0; i < 10; i++) {
    //     do_fuzz(i, i, i);
    // }

    printf("Goodbye!\n");
    return 0;
}