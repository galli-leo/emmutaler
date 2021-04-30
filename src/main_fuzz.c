#include <stdio.h>
#include "rom/rom_extra.h"
#include "rom.h"
#include <unistd.h>
#include <stdlib.h>
#include "debug/signals.h"
#include "platform/chipid.h"
#include "hexdump.h"
#include <assert.h>
#include <string.h>

image_info img_info;

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

void setup_heap()
{
    void* heap_base = 0x19C028000LL;
    uint64_t g_heap_cookie[2] = { 0xa7fa3a2e367917fcULL, 0x64636b783132322fULL };
    printf("Initializing heap at %p\n", heap_base);
    rom_heap_set_cookie(g_heap_cookie); // TODO: Randomized heap cookie?
    printf("Randomized heap cookie...\n");
    rom_heap_add_chunk(heap_base, 0x8000uLL, 1);
    printf("Done with heap\n");
}

int do_fuzz(void* address, uint64_t img_size, uint64_t another_one)
{
    uint64_t saved_image_size = img_size;
    uint64_t really_boi = saved_image_size + 0x10;
    img_info.imageLength = img_size;
#if DEBUG
    printf("Running with size: 0x%lx, %p, 0x%lx, 0x%lx\n", img_size, address, another_one, img_info.imageLength);
#endif
    //printf("asdf: 0x%x vs 0x%x vs 0x%x\n", img_size, saved_image_size, really_boi);
    // if (img_size + 10 > 10) {
        uint64_t image_size = img_info.imageLength;//(img_size & 0x2000) + 0x4000; // align to next higher power of 0x2000, otherwise complaints will come :(
        unsigned char* rom_bytes = (unsigned char*) rom_img_start;
        // printf("ROM IMAGE AT: %p, 0x%x, 0x%x, 0x%x\n", rom_img_start, image_size, saved_image_size, img_info.imageLength);
#if ALLOW_OOB
        memset(&rom_bytes[image_size], 0, 0x10000 - image_size);
#else
        memset(&rom_bytes[image_size], 0x42, 0x10000 - image_size);
#endif
        uint32_t types = 'ibec';
        // printf("Types: 0x%x\n", types);
        uint32_t result = rom_image_load(&img_info, &types, 1u, 0LL, rom_img_start, image_size, 0LL);
        if (result != 0) {
            #if DEBUG
            printf("Failed to load image: %d\n", result);
            #endif
        } else {
            printf("Successfully loaded image at %p\n", rom_img_start);
            img_func func = (img_func) rom_img_start;
            int res = func();
            if (res == 420) {
                #if DEBUG
                printf("Valid image ran ok, so that's good, I guess\n");
                #endif
                // exit(0);
            } else if (res == 69) {
                printf("Invalid image ran ok, that's not good (for apple)\n");
                // raise(SIGSEGV);
                abort();
                // assert(false);
                // exit(3);
            } else {
                printf("Unknown return value %d\n", res);
                // exit(4);
            }
        }
#if ALLOW_OOB
#else
        for (int i = image_size; i < 0x10000; i++) {
            if (rom_bytes[i] != 0x42) {
                printf("OUT OF BOUNDS WRITE TO %p\n", &rom_bytes[i]);
                // break;
                assert(false);
            }
        }
#endif

    // } else {
    //     printf("HAHA NO GOOD!\n");
    // }
    // void* prev_pc = __builtin_return_address(0);
    // void* fp = __builtin_frame_address(0);
    // printf("RETURN ADDRESS: %p\n", prev_pc);
    return 1; // I think this is needed, so that the return is not compiled out. or something idk.
}

int main(int argc, char* argv[]) {
    install_signal_handler();
    setup_manifest();
    setup_heap();

    img_info.imageLength = 0;
    img_info.imagePrivateMagic = 'Memz';
    img_info.imageOptions = IMAGE_OPTION_LOCAL_STORAGE;
    img_info.imagePrivate = rom_img_start;

    printf("Allocated image info at %p, buffer at: %p\n", &img_info, rom_img_start);

    do_fuzz(0, 0, 0);
#if DEBUG
    printf("Goodbye!\n");
#endif
    return 0;
}