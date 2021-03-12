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

void vbar_el1_handler(uint64_t addr)
{
    printf("Handling vbar_el1_here, exception vector base is %p\n", addr);
}

void arch_cpu_init_handler()
{
    printf("Pretending to do arch_cpu_init here...\n");
}

void report_no_boot_image_handler(uint32_t result)
{
    some_kind_of_report_handler(result, 0, 0, 0);
}

void some_kind_of_report_handler(uint32_t result, int a2, int a3, int a4)
{
    printf("[*] REPORTING IN: 0x%08x (0x%x, 0x%x, 0x%x)\n", result, a2, a3, a4);
    void* prev_pc = __builtin_return_address(0);
    void* fp = __builtin_frame_address(0);
    printf("STACKTRACE:\n");
    print_stacktrace(prev_pc, fp);
}

extern void buggy(void* address);

int main(int argc, char* argv[]) {
    install_signal_handler();

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
    long image_size = ftell(image_file);
    fseek(image_file, 0, SEEK_SET);
    printf("Image is 0x%x bytes large\n", image_size);
    char* image_buffer = malloc(image_size);
    long result = fread(image_buffer, image_size, 1, image_file);
    if (result != 1) {
        printf("Failed to read in image, expected 0x%x, but read 0x%x\n", image_size, result);
        exit(1);
    }

    image_info_t* image_info = malloc(sizeof(image_info_t));
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
    }

    // printf("Hello World! ROM LOADED AT: %p, %p\n", &rom_start, &rom_platform_start);
    // sub_function();
    // fake_rom_start();
    // rom_platform_start();
    printf("Goodbye!\n");
    return 0;
}