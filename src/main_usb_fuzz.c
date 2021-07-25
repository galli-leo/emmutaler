#include <pthread.h>
#include "event/event.h"
#include "heap/heap.h"
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
#include "usb/usb_msg.h"

#define MSG_BUF_SIZE (0x10000)

uint8_t message_buf[MSG_BUF_SIZE] = {};

int usb_main()
{
    log_info("Running USB stuff");
    setup_usb();

    // struct usb_device_descriptor dev_desc = {};
    // transmission_response_t resp = send_get_descriptor(USB_DT_DEVICE, 0, 0, &dev_desc, sizeof(dev_desc));
    // log_info("got device descriptor(%d): %x:%x", resp, dev_desc.idVendor, dev_desc.idProduct);

    // char buf[256] = {};
    // resp = send_get_string_descriptor(dev_desc.iSerialNumber, 0, buf, sizeof(buf) - 1);
    // log_info("serial number(%d): %s", dev_desc.iSerialNumber, buf);

    // sleep(1);

    // send_clr_status();
    // send_abort();
    // send_clr_status();
    // send_abort();
    // resp = send_get_descriptor(USB_DT_DEVICE, 0, 0, &dev_desc, sizeof(dev_desc));
    // log_info("got device descriptor(%d): %x:%x", resp, dev_desc.idVendor, dev_desc.idProduct);
    // send_get_descriptor(USB_DT_DEVICE, 0, 0, &dev_desc, sizeof(dev_desc));
    // send_get_descriptor(USB_DT_DEVICE, 0, 0, &dev_desc, sizeof(dev_desc));
    // send_get_descriptor(USB_DT_DEVICE, 0, 0, &dev_desc, sizeof(dev_desc));
    // send_abort();
    // send_get_descriptor(USB_DT_DEVICE, 0, 0, &dev_desc, sizeof(dev_desc));
    // send_get_descriptor(USB_DT_DEVICE, 0, 0, &dev_desc, sizeof(dev_desc));
    // send_get_descriptor(USB_DT_DEVICE, 0, 0, &dev_desc, sizeof(dev_desc));

    // sleep(1);

    finish_usb();
}

void __attribute__ ((noinline)) do_fuzz(uint8_t* buffer, size_t length, size_t i_hate_this)
{
    asm("");
    // snapshot_heap();
    start_usb_thread();
    log_info("Do we hate it?: %d", i_hate_this + 2 - length);
    process_messages(buffer, length);
    log_info("We hate it!: %d", i_hate_this - 10 - length);
    finish_usb();
    // restore_snapshot();
    // log_info("Heap should not have been corrupted!");
    // rom_heap_verify();
    asm("");
}

int main(int argc, char* argv[]) {
    install_signal_handler();
    setup_manifest();
    log_init();

    log_info("iBoot version: %s (%s)", IBOOT_VERSION, CHIP_STR);

    // if (argc < 1) {
    //     printf("Usage: %s usb_msg.seq\n", argv[0]);
    //     exit(0);
    // }

    setup_usb();

    long msg_file_size = 0;

    if (argc > 1) {
        FILE* msg_file = fopen(argv[1], "r");
        if (!msg_file) {
            log_error("Failed to open usb message file!");
            return -1;
        }

        fseek(msg_file, 0, SEEK_END);
        msg_file_size = ftell(msg_file);

        fseek(msg_file, 0, SEEK_SET);
        log_info("file is 0x%x bytes large", msg_file_size);
        if (msg_file_size > MSG_BUF_SIZE) {
            msg_file_size = MSG_BUF_SIZE;
        }

        long result = fread(message_buf, msg_file_size, 1, msg_file);
        if (result != 1) {
            log_error("Failed to read in usb message file, expected 0x%x, but read 0x%x", msg_file_size, result);
            return -2;
        }
    }

    do_fuzz(message_buf, msg_file_size, MSG_BUF_SIZE);

    // process_file_messages(argv[1]);

    // sleep(1);

    // msleep(1000);

    log_info("Done with file messages, finishing up USB now");
    // Cannot do this, since then it is terminated the first time round!
    // finish_usb();

    return 0;
}