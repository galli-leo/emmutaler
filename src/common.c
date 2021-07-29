#include "common.h"
#include "rom.h"
#include "debug/log.h"
#include "rom/rom_extra.h"
#include "platform/chipid.h"
#include "usb/usb.h"
#include <pthread.h>
#include "heap/heap.h"

const void* rom_img_start = &__start_rom_img;

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

static const void* heap_base = 0x19C028000LL;
static const size_t heap_size = 0x8000;

void setup_heap()
{
    // TODO: Make this more nicely configurable!
    // uint64_t g_heap_cookie[2] = { 0xa7fa3a2e367917fcULL, 0x64636b783132322fULL };
    // log_info("Initializing heap at %p", heap_base);
    // rom_heap_set_cookie(g_heap_cookie); // TODO: Randomized heap cookie?
    // log_info("Randomized heap cookie...");
    // rom_heap_add_chunk(heap_base, heap_size, 1);
    // log_info("Done with heap");
    init_heap();
}

void setup_entropy()
{
    log_info("Initializing entropy source");
    rom_init_entropy_source(heap_base, heap_size);
}

void load_and_test_image(struct image_info *loaded_image, uint32_t type, void *load_address, uint64_t load_length)
{
    loaded_image->imageOptions |= IMAGE_OPTION_GREATER_EPOCH | IMAGE_OPTION_REQUIRE_TRUST;
    uint32_t result = rom_image_load(loaded_image, &type, 1u, NULL, load_address, load_length, NULL);
    if (result != 0) {
        log_info("Failed to load image: %d", result);
    } else {
        log_info("Successfully loaded image at %p", rom_img_start);
        img_func func = (img_func) rom_img_start;
        int res = func();
        if (res == 420) {
            log_info("Valid image ran ok, so that's good, I guess");
            // exit(0);
        } else if (res == 69) {
            log_warn("Invalid image ran ok, that's not good (for apple)");
            // raise(SIGSEGV);
            abort();
            // assert(false);
            // exit(3);
        } else {
            log_warn("Unknown return value %d", res);
            abort();
            // exit(4);
        }
    }
#if ALLOW_OOB
#else
        // printf("Checking for out of bounds writes\n");
        // for (int i = image_size; i < 0x10000; i++) {
        //     if (rom_bytes[i] != 0x42) {
        //         printf("OUT OF BOUNDS WRITE TO %p\n", &rom_bytes[i]);
        //         // break;
        //         // exit(69);
        //         abort();
        //     }
        // }
#endif
}

struct image_info* image_create_from_memory(void* load_address, size_t loaded_length)
{
    image_info* image_info = malloc(sizeof(struct image_info));
    image_info->imageLength = loaded_length;
    image_info->imagePrivateMagic = IMAGE_MEMORY_INFO_MAGIC;
    image_info->imageOptions = IMAGE_OPTION_LOCAL_STORAGE;
    image_info->imagePrivate = load_address;

    return image_info;
}

bool main_should_exit = false;
bool main_did_exit = false;
pthread_mutex_t exit_lock;
pthread_cond_t exit_cond;
pthread_t usb_main_thd;

void signal_exit()
{
    pthread_cond_signal(&exit_cond);
    pthread_mutex_unlock(&exit_lock);
}

void* usb_main_thread(void* args)
{
    // while (true) {
        // log_info("Starting usb_main_thread");
        pthread_mutex_lock(&exit_lock);
        while (!main_should_exit) {
            log_info("Starting usb_main_thread");
            // Signal before starting USB procedure
            // actually, no that seems to result in a deadlock at points.
            // signal_exit();
            int res = rom_getDFUImage(rom_img_start, IMG_SIZE);
            if (res <= 0) {
                log_info("getDFUImage failed: %d", res);
            } else {
                log_info("getDFUImage success: %d", res);
                if (IMG_SIZE < res) {
                    log_error("WTF? getDFUImage result is larger than IMG_SIZE (%d > %d)", res, IMG_SIZE);
                    // Should probably be an abort, since that could cause issues in SecureROM as well.
                    abort();
                    continue;
                }
                struct image_info* img_info = image_create_from_memory(rom_img_start, res);
                load_and_test_image(img_info, DEFAULT_TYPE, rom_img_start, res);
                free(img_info);
            }
            pthread_mutex_lock(&exit_lock);
        }
        
        main_did_exit = true;

        pthread_cond_signal(&exit_cond);

        pthread_mutex_unlock(&exit_lock);
    // }


    return NULL;
}

void setup_usb()
{
    // Allow mode mem access, so that we can download DFU image at an arbitrary address!
    rom_security_protect_memory(rom_img_start, IMG_SIZE, false);
    pthread_mutex_init(&exit_lock, NULL);
    pthread_cond_init(&exit_cond, NULL);
    // rom_security_mode |= 0x10000;
    // rom_insecure_memory_start = rom_img_start;
    // rom_insecure_memory_end = rom_img_start + IMG_SIZE;
    setup_entropy();
    setup_heap();
    initialize_manager(&usb_mgr);
    log_info("usb_main: %p", &usb_main_thd);
}

void start_usb_thread()
{
    main_should_exit = false;
    main_did_exit = false;
    int res = pthread_create(&usb_main_thd, NULL, usb_main_thread, NULL);
    // wait_event(&usb_mgr.usb_ready);
    log_info("USB started!");
}

transmission_response_t transmit_setup_nowait(uint8_t bmRequestType, uint8_t bRequest, uint16_t wIndex, uint16_t wLength, uint16_t wValue, void *outBuf, size_t outLen)
{
    struct usb_device_request req = {};
    req.bmRequestType = bmRequestType;
    req.bRequest = bRequest;
    req.wIndex = wIndex;
    req.wLength = wLength;
    req.wValue = wValue;
    return transmit_usb_buffer(&req, sizeof(struct usb_device_request), true, outBuf, outLen, true);
}

transmission_response_t send_std_request_nowait(uint8_t request, uint8_t direction, uint8_t recipient, uint16_t wIndex, uint16_t wLength, uint16_t wValue, void *outBuf, size_t outLen)
{
    return transmit_setup_nowait(USB_REQ_TYPE_STANDARD | recipient | direction, request, wIndex, wLength, wValue, outBuf, outLen);
}

void send_dfu_request_nowait(dfu_request_type_t request, uint8_t direction)
{
    transmit_setup_nowait(USB_REQ_TYPE_CLASS | USB_REQ_RECIPIENT_INTERFACE | direction, request, 0, 0, 0, NULL, -1);
}

void send_abort_nowait()
{
    send_dfu_request_nowait(DFU_ABORT, USB_REQ_HOST2DEVICE);
}

void finish_usb()
{
    
    pthread_mutex_lock(&exit_lock);
    main_should_exit = true;
    while (!main_did_exit) {
        send_abort_nowait();
        pthread_cond_wait(&exit_cond, &exit_lock);
        if (!main_did_exit) {
            send_abort();
        }
    }
    pthread_mutex_unlock(&exit_lock);

    log_info("waiting on usb thread exit");
    pthread_join(usb_main_thd, NULL);
}

void finish_no_join()
{
    send_abort();
    return;
    pthread_mutex_lock(&exit_lock);
    main_should_exit = true;
    while (!main_did_exit) {
        send_abort_nowait();
        pthread_cond_wait(&exit_cond, &exit_lock);
        if (!main_did_exit) {
            send_abort();
        }
    }

    main_did_exit = false;
    main_should_exit = false;
    pthread_mutex_unlock(&exit_lock);
}