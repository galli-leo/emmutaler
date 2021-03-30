#include <stdio.h>
#include "rom/rom_extra.h"
#include "rom.h"
#include <unistd.h>
#include <stdlib.h>
#include "debug/signals.h"
#include "platform/chipid.h"
#include "hexdump.h"
#include <assert.h>

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

void setup_manifest()
{
    uint64_t board_id = 6;
    uint64_t epoch = 1;
    uint64_t prod_mode = 1;
    uint64_t sec_mode = 1;
    uint64_t ecid = 0x1538810200802e;
    uint64_t sec_dom = 1;
    set_board_id(board_id);
    set_security_epoch(epoch);
    set_raw_prod_mode(prod_mode);
    set_secure_mode(sec_mode);
    set_ecid(ecid);
    set_sec_domain(sec_dom);
    set_curr_prod_mode(prod_mode);
    set_uk_fuse(0);
    set_uk_fuse2(0);
}

extern void buggy(void* address);

int main(int argc, char* argv[]) {
    install_signal_handler();
    setup_manifest();
    // buggy(0x10001d760);
    // dini_muetter(0x40001d760);

    if (argc < 1) {
        printf("Usage: %s rom_image\n", argv[0]);
        exit(0);
    }

    char* image_filename = argv[1];
    printf("Loading image from %s\n", image_filename);

    FILE* image_file = fopen(image_filename, "r");
    if (!image_file) {
        printf("Failed to open image file!\n");
        exit(1);
    }

    fseek(image_file, 0, SEEK_END);
    long act_image_size = ftell(image_file);
    long image_size = (act_image_size & 0x2000) + 0x4000; // align to next higher power of 0x2000, otherwise complaints will come :(
    if (act_image_size > 0x10000) {
        printf("Image is too large: 0x%x\n", act_image_size);
        exit(2);
    }
    fseek(image_file, 0, SEEK_SET);
    printf("Image is 0x%x bytes large\n", image_size);
    // char* image_buffer = malloc(image_size);
    char* image_buffer = rom_img_start;
    long result = fread(image_buffer, act_image_size, 1, image_file);
    if (result != 1) {
        printf("Failed to read in image, expected 0x%x, but read 0x%x\n", act_image_size, result);
        exit(1);
    }

    image_info* image_info = malloc(sizeof(image_info));
    image_info->imageLength = image_size;
    image_info->imagePrivateMagic = 'Memz';
    image_info->imageOptions = IMAGE_OPTION_LOCAL_STORAGE;
    image_info->imagePrivate = image_buffer;

    printf("Allocated image info at %p, buffer at: %p\n", image_info, image_buffer);

    void* heap_base = 0x19C028000LL;
    uint64_t g_heap_cookie[2] = { 0xa7fa3a2e367917fcULL, 0x64636b783132322fULL };
    printf("Initializing heap at %p\n", heap_base);
    rom_heap_set_cookie(g_heap_cookie); // TODO: Randomized heap cookie?
    printf("Randomized heap cookie...\n");
    rom_heap_add_chunk(heap_base, 0x8000uLL, 1);
    printf("Done with heap\n");

    uint32_t types = 'ibec';
    result = rom_image_load(image_info, &types, 1u, 0LL, image_buffer, image_size, 0LL);
    if (result != 0) {
        printf("Failed to load image: %d\n", result);
    } else {
        printf("Successfully loaded image at %p\n", image_buffer);
        img_func func = (img_func) image_buffer;
        int res = func();
        if (res == 420) {
            printf("Valid image ran ok, so that's good, I guess\n");
            exit(0);
        } else if (res == 69) {
            printf("Invalid image ran ok, that's not good (for apple)\n");
            assert(false);
            exit(3);
        } else {
            printf("Unknown return value %d\n", res);
            exit(4);
        }
        // hexdump(image_buffer, 0x100);
    }

    // printf("Hello World! ROM LOADED AT: %p, %p\n", &rom_start, &rom_platform_start);
    // sub_function();
    // fake_rom_start();
    // rom_platform_start();
    printf("Goodbye!\n");
    return 0;
}