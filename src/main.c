#include <pthread.h>
#include "event/event.h"
#include "rom/rom_extra.h"
#include "rom.h"
#include <unistd.h>
#include <stdlib.h>
#include "debug/signals.h"
#include "platform/chipid.h"
#include "hexdump.h"
#include <assert.h>
#include "config/version.h"
#include "debug/log.h"
#include <stdio.h>
#include "usb/usb.h"
#include "common.h"


int main(int argc, char* argv[]) {
    install_signal_handler();
    setup_manifest();
    log_init();

    log_info("iBoot version: %s (%s)\n", IBOOT_VERSION, CHIP_STR);

    if (argc < 1) {
        printf("Usage: %s rom_image\n", argv[0]);
        exit(0);
    }

    char* image_filename = argv[1];
    log_info("Loading image from %s", image_filename);

    FILE* image_file = fopen(image_filename, "r");
    if (!image_file) {
        log_error("Failed to open image file!");
        exit(1);
    }

    fseek(image_file, 0, SEEK_END);
    long act_image_size = ftell(image_file);
    long image_size = act_image_size;//(act_image_size & 0x2000) + 0x4000; // align to next higher power of 0x2000, otherwise complaints will come :(
    if (act_image_size > IMG_SIZE) {
        log_error("Image is too large: 0x%x", act_image_size);
        exit(2);
    }
    fseek(image_file, 0, SEEK_SET);
    log_info("Image is 0x%x bytes large\n", image_size);
    // char* image_buffer = malloc(image_size);
    char* image_buffer = rom_img_start;
    long result = fread(image_buffer, act_image_size, 1, image_file);
    if (result != 1) {
        log_error("Failed to read in image, expected 0x%x, but read 0x%x", act_image_size, result);
        exit(1);
    }

    image_info* image_info = image_create_from_memory(image_buffer, act_image_size);

    log_info("Allocated image info at %p, buffer at: %p", image_info, image_buffer);

    setup_heap();

    load_and_test_image(image_info, DEFAULT_TYPE, rom_img_start, IMG_SIZE);

    return 0;
}