#include "event/event.h"
#include "usb.h"

usb_manager_t usb_mgr = {
    // .usb_ready = {
    //     .cond_var_lock = PTHREAD_MUTEX_INITIALIZER,
    //     .cond_var = PTHREAD_COND_INITIALIZER,
    // }
};

void initialize_manager(usb_manager_t* manager)
{
    // initialize_event(&manager->usb_ready);
    pthread_mutex_init(&manager->ready_lock, NULL);
    pthread_cond_init(&manager->ready, NULL);
    manager->is_ready = false;
    manager->did_abort = false;
    manager->did_stall = false;
}