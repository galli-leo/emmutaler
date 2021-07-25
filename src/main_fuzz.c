#include <stdio.h>
#include "common.h"
#include "rom/rom_extra.h"
#include "rom.h"
#include <unistd.h>
#include <stdlib.h>
#include "debug/signals.h"
#include "platform/chipid.h"
#include "hexdump.h"
#include <assert.h>
#include <string.h>
#include "debug/log.h"

image_info* img_info;


int do_fuzz(void* address, uint64_t img_size, uint64_t another_one)
{
    img_info->imageLength = img_size;
    img_info->imageAllocation = img_size;
    load_and_test_image(img_info, DEFAULT_TYPE, rom_img_start, img_size);
    return 1;
}

int main(int argc, char* argv[]) {
    install_signal_handler();
    setup_manifest();
    setup_heap();

    img_info = image_create_from_memory(rom_img_start, IMG_SIZE);

    log_info("Allocated image info at %p, buffer at: %p", &img_info, rom_img_start);

    do_fuzz(0, 0, 0);
    return 0;
}