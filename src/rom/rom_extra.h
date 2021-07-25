#ifndef __ROM_EXTRA_H
#define __ROM_EXTRA_H

#include <stdint.h>
#include <stdbool.h>

#define IMAGE_MEMORY_INFO_MAGIC		'Memz'
#define IMAGE2_IMAGE_INFO_MAGIC		'img2'
#define IMAGE3_IMAGE_INFO_MAGIC		'img3'
#define IMAGE4_IMAGE_INFO_MAGIC		'img4'

#define IMAGE_OPTION_GREATER_EPOCH	(1 << 0)	// Allow platform epoch or greater
#define IMAGE_OPTION_REQUIRE_TRUST	(1 << 1)	// Regardless of security, require image
							// trust
#define IMAGE_OPTION_LOCAL_STORAGE	(1 << 2)	// Image came from local (personalised) storage
#define IMAGE_OPTION_NEW_TRUST_CHAIN	(1 << 3)	// New chain of trust. Image load library can use this information
							// enforce various policies.

#define IMAGE_OPTION_JUST_LOAD		(1 << 8)	// Just load the whole image, don't validate or look for a payload
#define IMAGE_OPTION_MEMORY		(1 << 9)	// Image comes from a memory bdev, so its hash isn't personalized

extern void __start_rom_gpio;
extern void __start_rom_img;

typedef int (*img_func)();
// void* start_rom_gpio = &__start_rom_gpio;


#endif /* __ROM_EXTRA_H */
