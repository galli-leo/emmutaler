#ifndef __USB_H
#define __USB_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include "event/event.h"
#include "rom.h"

//====================================================================
// USB Descriptor Types
//====================================================================
#define USB_DT_DEVICE				1
#define USB_DT_CONFIGURATION                    2
#define USB_DT_STRING                           3
#define USB_DT_INTERFACE                        4
#define USB_DT_ENDPOINT                         5
#define USB_DT_DEVICE_QUALIFIER                 6
#define USB_DT_OTHER_SPEED_CONFIGURATION	7

//====================================================================
// USB Endpoints Types
//====================================================================
#define USB_ENDPOINT_CONTROL            0x00
#define USB_ENDPOINT_ISOCHRONOUS        0x01
#define USB_ENDPOINT_BULK               0x02
#define USB_ENDPOINT_INTERRUPT          0x03

//====================================================================
// USB Standard Request Types
//====================================================================
#define USB_REQ_GET_STATUS              0x00
#define USB_REQ_CLEAR_FEATURE           0x01
#define USB_REQ_SET_FEATURE             0x03
#define USB_REQ_SET_ADDRESS             0x05
#define USB_REQ_GET_DESCRIPTOR          0x06
#define USB_REQ_SET_DESCRIPTOR          0x07
#define USB_REQ_GET_CONFIGURATION       0x08
#define USB_REQ_SET_CONFIGURATION       0x09
#define USB_REQ_GET_INTERFACE           0x0A
#define USB_REQ_SET_INTERFACE           0x0B

//====================================================================
// USB Feature Types
//====================================================================
#define USB_FEATURE_ENDPOINT_HALT		0x00
#define USB_FEATURE_REMOTE_WAKEUP		0x01
#define USB_FEATURE_TEST_MODE			0x02

//====================================================================
// USB Device Request Types
//====================================================================
#define USB_REQ_TYPE_STANDARD           0x00
#define USB_REQ_TYPE_CLASS              0x20
#define USB_REQ_TYPE_VENDOR             0x40

//====================================================================
// USB Class Codes
//====================================================================
#define USB_CLASS_INTERFACE_SPECIFIC         0
#define USB_CLASS_VENDOR_SPECIFIC            0xff

//====================================================================
// 		USB Chap9 specific consts
//====================================================================
#define USB_DT_DEVICE_SIZE		18
#define USB_DT_CONFIGURATION_SIZE      	9
#define USB_DT_INTERFACE_SIZE   	9
#define USB_DT_ENDPOINT_SIZE    	7
#define USB_DT_DEVICE_QUALIFIER_SIZE    10
#define USB_DT_STRING_SIZE		6

#define USB_DIR_OUT                     0
#define USB_DIR_IN                      0x80

#define USB_ENDPOINT_MASK               0x03
#define USB_ENDPOINT_NUMBER_MASK        0x0f
#define USB_ENDPOINT_DIR_MASK           0x80

#define USB_BCD_VERSION			0x0200

#define USB_REQ_DIRECTION_MASK          0x80
#define USB_REQ_TYPE_MASK               0x60
#define USB_REQ_RECIPIENT_MASK          0x1f

#define USB_REQ_DEVICE2HOST             0x80
#define USB_REQ_HOST2DEVICE             0x00

#define USB_REQ_RECIPIENT_DEVICE        0x00
#define USB_REQ_RECIPIENT_INTERFACE     0x01
#define USB_REQ_RECIPIENT_ENDPOINT      0x02
#define USB_REQ_RECIPIENT_OTHER         0x03

#define EP_NUM_MASK		(0x7f)
#define EP_DIR_MASK		(0x80)

#define ep_to_epnum(ep) ((ep) & EP_NUM_MASK)
#define ep_to_epdir(ep) ((ep) & EP_DIR_MASK)
#define ep_to_epindex(ep) ((2 * ep_to_epnum((ep))) + (ep_to_epdir((ep)) ? 0 :  1))

typedef struct endpoint
{
	uint32_t	endpoint_address;
	uint32_t 	max_packet_size;
	uint32_t 	attributes;
	uint32_t 	bInterval;
	
	uint32_t 	interrupt_status;
	
	uint32_t 	transfer_size;
	uint32_t 	packet_count;
	bool		is_active;
	
	struct usb_endpoint_instance *next_ep;
	
	struct usb_device_io_request *io_head;
	struct usb_device_io_request *io_tail;
    
	struct usb_device_io_request *completion_head;
	struct usb_device_io_request *completion_tail;
    
	int	 tx_fifo_number;
} endpoint_t;

typedef enum dfu_request_type {
    DFU_DETACH = 0,
    DFU_DNLOAD,
    DFU_UPLOAD,
    DFU_GETSTATUS,
    DFU_CLR_STATUS,
    DFU_GETSTATE,
    DFU_ABORT
} dfu_request_type_t;

typedef struct usb_manager {
    // Fired whenever usb is ready to receive commands.
    // event_t usb_ready;

    pthread_mutex_t ready_lock;
    pthread_cond_t ready;
    bool is_ready;

    // current response
    struct usb_device_io_request* response;
    // or maybe we stalled
    bool did_stall;
    // or maybe we aborted
    bool did_abort;

    endpoint_t endpoints[2];
} usb_manager_t;

extern usb_manager_t usb_mgr;

void initialize_manager(usb_manager_t* manager);

typedef enum transmission_response {
    // Got a response.
    OK = 0,
    // Stalled.
    STALLED,
    ABORTED,
    // Neither a response nor a stall.
    // Depending on the request, this is not necessarily an error.
    NO_RESPONSE,
    // Got a response, but outBuf was too small (i.e. outLen was too small)!
    OUT_TRUNC,
    NOT_READY,
} transmission_response_t;

/**
 * @brief "Transmits" a usb buffer to SecureROM. This should only be called, if usb is correctly initialized!
 * 
 * @param buffer The input buffer to transmit.
 * @param length The length of the buffer to transmit.
 * @param is_setup Whether this is a setup packet or not.
 * @param outBuf The output will be copied into here, if we received something.
 * @param outLen The length of the output buffer will be set here, if we receive one.
 * @param outStall 
 * @return status indicating whether we got a response, stalled or nothing at all.
 */
transmission_response_t transmit_usb_buffer(void* buffer, size_t length, bool is_setup, void* outBuf, size_t outLen, bool dontWait);

transmission_response_t transmit_setup(uint8_t bmRequestType, uint8_t bRequest, uint16_t wIndex, uint16_t wLength, uint16_t wValue, void* outBuf, size_t outLen);

transmission_response_t send_std_request(uint8_t request, uint8_t direction, uint8_t recipient, uint16_t wIndex, uint16_t wLength, uint16_t wValue, void* outBuf, size_t outLen);

transmission_response_t send_get_descriptor(uint8_t descType, uint8_t descIdx, uint16_t langId, void* outBuf, size_t outLen);

transmission_response_t send_get_string_descriptor(uint8_t descIdx, uint16_t langId, char* outBuf, size_t outLen);

// TODO: Ability to send data as well?
void send_dfu_request(dfu_request_type_t request, uint8_t direction);

extern struct usb_controller_functions *emmutaler_controller_init();

void send_get_status();
void send_abort();
void send_clr_status();

void cleanup_endpoint(uint32_t endpoint);
// void send_get_descriptor();

void send_event(usb_event_t event);

#endif /* __USB_H */
