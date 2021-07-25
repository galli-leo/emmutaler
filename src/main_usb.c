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
#include "usb/usb_msg.h"



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

int main(int argc, char* argv[]) {
    install_signal_handler();
    setup_manifest();
    log_init();

    log_info("iBoot version: %s (%s)\n", IBOOT_VERSION, CHIP_STR);

    if (argc < 1) {
        printf("Usage: %s usb_msg.seq\n", argv[0]);
        exit(0);
    }

    setup_usb();
    start_usb_thread();

    process_file_messages(argv[1]);

    // sleep(1);

    log_info("Done with file messages, finishing up USB now");

    finish_usb();

    log_info("Heap should not have been corrupted!");
    // rom_heap_verify();

    return 0;
}