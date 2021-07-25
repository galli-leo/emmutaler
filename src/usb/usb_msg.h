/**
 * @file usb_msg.h
 * @author Leonardo Galli (leonardo.galli@bluewin.ch)
 * @brief This file contains the definition of the messages read from files to fuzz USB in SecureROM.
 * @version 0.1
 * @date 2021-07-01
 * 
 * @copyright Copyright (c) 2021
 * 
 */
#ifndef __USB_MSG_H
#define __USB_MSG_H

#include <stdint.h>

/**
 * @brief The max size of a single EP0 packet (and hence a usb_msg's data part)
 * 
 */
#define EP0_MAX_PACKET_SIZE (0x40)

/**
 * @brief Maximum amount of sleep allowed, 10ms here.
 * 
 */
#define MAX_MSEC_SLEEP (10)

/**
 * @brief The type of a single message.
 * 
 */
typedef enum usb_msg_type {
    /**
     * @brief Message is a setup packet.
     * 
     */
    SETUP,
    /**
     * @brief Message is a data packet.
     * 
     */
    DATA,
    /**
     * @brief Message is actually an event, we "send" it with usb_core_event_handler.
     * 
     */
    EVENT,
    /**
     * @brief Message is actually a number of seconds to sleep.
     * 
     */
    SLEEP,
    /**
     * @brief Indicates we should do nothing, since we don't have a fixed number of messages, this shouldn't really be useful.
     * 
     */
    NOP
} usb_msg_type_t;

#pragma pack(push,1)

typedef struct usb_msg {
    /**
     * @brief Type (so actually usb_msg_type), but to ensure it's really 32bits, we need a fixed type here.
     * 
     */
    uint8_t type;

    /**
     * @brief This size will be passed as length to transmit_usb_buffer, however, it cannot be larger than EP0_MAX_PACKET_SIZE.
     * 
     */
    uint8_t data_size;

    /**
     * @brief The actual data of the packet, will be passed as buffer into transmit_usb_buffer (unless EVENT, SLEEP or NOP).
     * 
     */
    uint8_t data[EP0_MAX_PACKET_SIZE];
} usb_msg_t;

#pragma pack(pop)

void process_messages(void* buffer, uint64_t length);

int process_file_messages(const char* filename);

int msleep(long msec);

int save_proc_thread_state();
void restore_proc_thread_state();

int save_usb_thread_state();
void restore_usb_thread_state();

#endif /* __USB_MSG_H */
