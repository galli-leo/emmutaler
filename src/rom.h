#include <stdint.h>
#include <stdbool.h>

extern void rom_start_trampoline();
extern void rom_platform_start();
extern void rom_start();
extern void fake_rom_start();

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

struct image_info
{
  uint32_t imageLength;
  uint32_t imageAllocation;
  uint32_t imagePrivateMagic;
  uint32_t imageOptions;
  void *imagePrivate;
};

typedef struct image_info image_info_t;
extern void dini_muetter(uint64_t addr);
extern void rom_heap_set_cookie(uint64_t *result);
extern void rom_heap_add_chunk(void *chunk, size_t size, bool clear_memory);
extern int rom_image_load(struct image_info *image, const uint32_t *types, uint32_t count, uint32_t *actual, void **load_addr, size_t *load_len, size_t *unknown);