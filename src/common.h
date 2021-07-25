#ifndef __COMMON_H
#define __COMMON_H

#include <stdint.h>
#include "rom.h"

/**
 * @brief Set up the heap in preparation for any shenanigans ;)
 * 
 */
void setup_heap();

/**
 * @brief Set the up the properties from the manifest, such as the ECID in the correct IO mem locations.
 * 
 */
void setup_manifest();

void setup_entropy();

#define IBEC_TYPE ((uint32_t)'ibec')
#define DEFAULT_TYPE IBEC_TYPE
#define IMG_SIZE (0x10000)


/**
 * @brief Load the image at address (by calling rom_image_load) and potentially execute it.
 * This also verifies (if ALLOW_OOB) whether we did any OOB writes.
 * It also aborts, if we detect a non valid image being able to be ran.
 * 
 * @param address 
 * @param img_size 
 */
void load_and_test_image(struct image_info* loaded_image, uint32_t type, void* load_address, uint64_t load_length);

struct image_info* image_create_from_memory(void* load_address, size_t loaded_length);

/**
 * @brief Setup the USB part. This includes starting the "main" thread, that constantly tries to load a DFU image.
 * 
 */
void setup_usb();

void start_usb_thread();

/**
 * @brief Shuts down the USB thread.
 * 
 */
void finish_usb();

void finish_no_join();

pthread_t usb_main_thd;

const void* rom_img_start;

void signal_exit();
#endif /* __COMMON_H */
