#include "usb_msg.h"
#include "rom.h"
#include "usb.h"
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include "debug/log.h"
#include <setjmp.h>

jmp_buf proc_thread_state = {};
jmp_buf usb_thread_state = {};

int save_proc_thread_state()
{
    return setjmp(proc_thread_state);
}

void restore_proc_thread_state() {
    longjmp(proc_thread_state, 1);
}

int save_usb_thread_state()
{
    return setjmp(usb_thread_state);
}

void restore_usb_thread_state()
{
    longjmp(usb_thread_state, 1);
}

/* msleep(): Sleep for the requested number of milliseconds. */
int msleep(long msec)
{
    struct timespec ts;
    int res;

    if (msec < 0)
    {
        errno = EINVAL;
        return -1;
    }

    ts.tv_sec = msec / 1000;
    ts.tv_nsec = (msec % 1000) * 1000000;

    do {
        res = nanosleep(&ts, &ts);
    } while (res && errno == EINTR);

    return res;
}

// TODO: do we want to process unfinished messages as well?
void process_messages(void *buffer, uint64_t length)
{
    uint64_t num = length / sizeof(usb_msg_t);
    usb_msg_t* messages = (usb_msg_t*)buffer;
    for (int i = 0; i < num; i++)
    {
        log_info("Processing message %d", i);
        // If we panicked sending a message, continue on to the next message!
        if (save_proc_thread_state() != 0) {
            log_info("We panicked, but restored state, so hopefully fine?");
            continue;
        }
        usb_msg_t* curr = &messages[i];
        switch (curr->type) {
        case SETUP:
        case DATA:
        {
            uint32_t actLen = curr->data_size;
            transmit_usb_buffer(curr->data, actLen, curr->type == SETUP, NULL, 0x1000, false);
            break;
        }

        case EVENT:
        {
            usb_event_t event = *((usb_event_t*)curr->data);
            rom_usb_core_event_handler(event);
            bool* done_ptr = (bool*)0x19C010FC0;
            // log_info("done_addr: %p, %p", &rom_dfu_done, rom_dfu_done);
            if (*done_ptr) {
                // log_info("dfu_done");
                // usb_mgr.is_ready = false;
            }
            break;
        }

        case SLEEP:
        {
            uint64_t msec = *((uint64_t*)curr->data);
            if (msec > MAX_MSEC_SLEEP) msec = MAX_MSEC_SLEEP;
            
            msleep(msec);
            break;
        }

        case NOP:
        {
            break;
        }

        }
    }
}

int process_file_messages(const char *filename)
{
    log_info("Processing messages from %s", filename);

    FILE* msg_file = fopen(filename, "r");
    if (!msg_file) {
        log_error("Failed to open image file!");
        return -1;
    }

    fseek(msg_file, 0, SEEK_END);
    long msg_file_size = ftell(msg_file);

    fseek(msg_file, 0, SEEK_SET);
    log_info("file is 0x%x bytes large", msg_file_size);
    // char* image_buffer = malloc(image_size);
    unsigned char* msg_buffer = malloc(msg_file_size);
    long result = fread(msg_buffer, msg_file_size, 1, msg_file);
    if (result != 1) {
        log_error("Failed to read in image, expected 0x%x, but read 0x%x", msg_file_size, result);
        return -2;
    }

    process_messages(msg_buffer, msg_file_size);

    free(msg_buffer);

    return 0;
}