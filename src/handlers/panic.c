#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include "debug/log.h"
#include <pthread.h>
#include "common.h"
#include "usb/usb.h"
#include "usb/usb_msg.h"

void panic_handler()
{
    log_error("panic called, lets try restoring state (basically emulating a platform_reset)");
    // I lied, for now just abort
    // abort();
    // exit(69);
    if (pthread_self() == usb_main_thd) {
        log_warn("haven't implemented this yet!");
        // abort();
        exit(69);
    } else {
        // TODO: Better way to cleanup state after a panic??
        // unlock so we can send an abort
        pthread_mutex_unlock(&usb_mgr.ready_lock);
        finish_usb();
        exit(69);
        // hopefully this still works, otherwise we have a problem!
        send_abort();

        restore_proc_thread_state();
    }
    // exit(69);
}

void heap_panic_handler()
{
    printf("heap_panic called, this is bad (for apple)\n");
    abort();
}