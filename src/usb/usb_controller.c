#include "common.h"
#include "event/event.h"
#include "rom.h"
#include "types.h"
#include "usb.h"
#include "debug/log.h"
#include <pthread.h>
#include <stdlib.h>

void* fake_task;
void* fake_task_stck;

int emmutaler_usb_init()
{
    log_debug("usb_init");
    // We need this, so that heap can get fucked.
    // fake_task = rom_malloc(0x1b0);
	// fake_task_stck = rom_malloc(0x1000);
    return 0;
}

void emmutaler_usb_free()
{
    log_debug("usb_free");
    // rom_free(fake_task);
    // rom_free(fake_task_stck);
}

int emmutaler_usb_start()
{
    log_debug("usb_start_before_mutex");
    // log_info("rom_dfu_state: %d", rom_dfu_state);
    // rom_dfu_state = 8;
    // rom_usb_core_event_handler(USB_RESET);
    // signal_event(&usb_mgr.usb_ready);
    pthread_mutex_lock(&usb_mgr.ready_lock);

    log_debug("usb_start_after_mutex");

    // Needed, so that configuration is setup
    rom_usb_core_event_handler(USB_ENUM_DONE);
    // TODO: Would we be able to send packets on real hardware without this?
    // If so, the crash would happen there as well!

    usb_mgr.endpoints[0].is_active = true;
    usb_mgr.endpoints[1].is_active = true;
    usb_mgr.is_ready = true;
    pthread_cond_signal(&usb_mgr.ready);

    pthread_mutex_unlock(&usb_mgr.ready_lock);

    signal_exit();
    return 0;
}

void emmutaler_usb_stop()
{
    log_debug("usb_stop_before_mutex");

    pthread_mutex_lock(&usb_mgr.ready_lock);

    log_debug("usb_stop_after_mutex");

    cleanup_endpoint(0);
    cleanup_endpoint(0x80);

    usb_mgr.is_ready = false;

    // TODO: Signal here?

    pthread_mutex_unlock(&usb_mgr.ready_lock);
}


void emmutaler_usb_set_address(uint32_t new_address)
{
    // rom_dfu_state = 8;
    log_debug("usb_set_address(0x%x)", new_address);
}

int emmutaler_usb_get_connection_speed()
{
    log_debug("usb_get_connection_speed");
    return 0x1000; // TODO: not this value lmao
}

void emmutaler_usb_activate_endpoint(uint32_t endpoint, int type, int max_packet_size, int interval)
{
    log_debug("usb_activate_endpoint(0x%x, 0x%x, 0x%x, 0x%x)", endpoint, type, max_packet_size, interval);
}

void emmutaler_usb_do_endpoint_io(struct usb_device_io_request* req)
{
    log_debug("usb_do_endpoint_io(%p)", req);
    req->return_count = 0;
	req->status = -1;
	req->next = NULL;

    uint32_t epindex = ep_to_epindex(req->endpoint);
	endpoint_t* ep = &usb_mgr.endpoints[epindex];

    if (!ep->is_active) {
        rom_usb_core_complete_endpoint_io(req);
    }

    // pending IOs
	if(ep->io_head) {
		ep->io_tail->next = req;
		ep->io_tail = req;
        return;
	}
    
	// no Pending IOs
	ep->io_head = ep->io_tail = req;
    

    if (req != NULL)
    {
        #define debug_req(prop, format) log_debug("req->" #prop " = " format, req->prop)
        // debug_req(endpoint, "0x%x");
        // debug_req(io_buffer, "%p");
        // debug_req(status, "%d");
        // debug_req(io_length, "0x%x");
        // debug_req(return_count, "%d");
        // debug_req(callback, "%p");
        // debug_req(next, "%p");
        usb_mgr.response = req;
        // log_debug("req->endpoint = 0x%x", req->endpoint);
    }
}

void emmutaler_usb_stall_endpoint(uint32_t endpoint, bool stall)
{
    usb_mgr.did_stall = stall;
    log_debug("usb_stall_endpoint(0x%x, %s)", endpoint, stall ? "true" : "false");
}

void emmutaler_usb_reset_endpoint_data_toggle(uint32_t endpoint)
{
    log_debug("usb_reset_endpoint_data_toggle(0x%x)", endpoint);
}

bool emmutaler_usb_is_endpoint_stalled(uint32_t endpoint)
{
    log_debug("usb_is_endpoint_stalled(0x%x)", endpoint);
    return false;
}

void emmutaler_usb_do_test_mode(uint32_t selector)
{
    log_debug("usb_do_test_mode(0x%x)", selector);
}

void cleanup_endpoint(uint32_t endpoint)
{
    struct usb_device_io_request *aborted_list;
	struct usb_device_io_request *completed_list;
	endpoint_t *ep;
	u_int32_t epindex;
	u_int32_t ep_num;

    log_debug("cleanup_endpoint(0x%x)", endpoint);


    ep_num = ep_to_epnum(endpoint);

	epindex = ep_to_epindex(endpoint);

	ep = &usb_mgr.endpoints[epindex];
	
	// Check if this endpoint is valid
	if(!ep->is_active) {
        return;
	}

    ep->interrupt_status = 0;
	ep->transfer_size = ep->packet_count = 0;
	
	completed_list = ep->completion_head;
	ep->completion_head = ep->completion_tail = NULL;
    
	aborted_list = ep->io_head;
	ep->io_head = ep->io_tail = NULL;
    
	// First return all completed transactions
	while(completed_list) {
		struct usb_device_io_request *completed_req = completed_list;
		completed_list = completed_req->next;
		rom_usb_core_complete_endpoint_io(completed_req);
	}
    
	// Then return the aborted transactions
	while(aborted_list) {
		struct usb_device_io_request *aborted_req = aborted_list;
		aborted_list = aborted_req->next;
		aborted_req->status = 1;
		rom_usb_core_complete_endpoint_io(aborted_req);
	}
}

void emmutaler_usb_abort_endpoint(uint32_t endpoint)
{
    log_debug("usb_abort_endpoint(0x%x)", endpoint);
}

void emmutaler_usb_deactivate_endpoint(uint32_t endpoint)
{
    log_debug("usb_deactivate_endpoint(0x%x)", endpoint);
}

static const struct usb_controller_functions emmutaler_controller_functions = {
	.init = emmutaler_usb_init,
	.free_func = emmutaler_usb_free,
	.start = emmutaler_usb_start,
	.stop = emmutaler_usb_stop,
	.set_address = emmutaler_usb_set_address,
	.get_connection_speed = emmutaler_usb_get_connection_speed,
	.activate_endpoint = emmutaler_usb_activate_endpoint,
	.do_endpoint_io = emmutaler_usb_do_endpoint_io,
	.stall_endpoint = emmutaler_usb_stall_endpoint,
	.reset_endpoint_data_toggle = emmutaler_usb_reset_endpoint_data_toggle,
	.is_endpoint_stalled = emmutaler_usb_is_endpoint_stalled,
	.do_test_mode = emmutaler_usb_do_test_mode,
	.abort_endpoint = emmutaler_usb_abort_endpoint,
	.deactivate_endpoint = emmutaler_usb_deactivate_endpoint,
};

usb_controller_functions* emmutaler_controller_init()
{
    log_info("emmutaler_controller_init");
    return &emmutaler_controller_functions;
}

static bool data_phase = false;

transmission_response_t transmit_usb_buffer(void *buffer, size_t length, bool is_setup, void *outBuf, size_t outLen, bool dontWait)
{
    bool* done_ptr = (bool*)0x19C010FC0;
    log_debug("transmit_usb_buffer_before_lock(%s)", dontWait ? "true" : "false");
    pthread_mutex_lock(&usb_mgr.ready_lock);
    log_debug("did take lock");
    if (*done_ptr) {
        log_info("dfu_done");
        usb_mgr.is_ready = false;
    }
    if (!usb_mgr.is_ready && dontWait) {
        pthread_mutex_unlock(&usb_mgr.ready_lock);
        log_info("Not ready yet");
        return NOT_READY;
    }
    while (!usb_mgr.is_ready)
        pthread_cond_wait(&usb_mgr.ready, &usb_mgr.ready_lock);
    
    log_debug("transmit_usb_buffer(%p, %d, %s)", buffer, length, is_setup ? "true" : "false");
    usb_mgr.did_stall = false;
    usb_mgr.did_abort = false;
    usb_mgr.response = NULL;
    rom_usb_core_handle_usb_control_receive(buffer, is_setup, length, &data_phase);
    log_debug("transmit_usb_buffer:response: %p (%d), %s", usb_mgr.response != NULL ? usb_mgr.response->io_buffer : NULL, usb_mgr.response != NULL ? usb_mgr.response->io_length : 0, usb_mgr.did_stall ? "true" : "false");

    transmission_response_t ret = NO_RESPONSE;

    if (usb_mgr.response != NULL)
    {
        size_t to_copy = usb_mgr.response->io_length;
        ret = OK;
        if (to_copy > outLen)
        {
            to_copy = outLen;
            ret = OUT_TRUNC;
        }
        if (outBuf != NULL)
            memcpy(outBuf, usb_mgr.response->io_buffer, outLen);

        if (usb_mgr.response->io_length == 6)
        {
            usb_dfu_status_request* dfu_status = (usb_dfu_status_request*)usb_mgr.response->io_buffer;
            log_info("transmit_usb_buffer: status: %d, %d", dfu_status->bStatus, dfu_status->bState);
        }
#if DEBUG
#endif
        // rom_usb_core_complete_endpoint_io(usb_mgr.response);
        usb_mgr.response = NULL;
    }

    if (usb_mgr.did_stall) ret = STALLED;

    // TODO: Make this less cringe!
    // log_info("done_addr: %p, %p", &rom_dfu_done, rom_dfu_done);
    if (*done_ptr) {
        log_info("dfu_done");
        // usb_mgr.is_ready = false;
    }

    pthread_mutex_unlock(&usb_mgr.ready_lock);

    return ret;
}

transmission_response_t transmit_setup(uint8_t bmRequestType, uint8_t bRequest, uint16_t wIndex, uint16_t wLength, uint16_t wValue, void *outBuf, size_t outLen)
{
    struct usb_device_request req = {};
    req.bmRequestType = bmRequestType;
    req.bRequest = bRequest;
    req.wIndex = wIndex;
    req.wLength = wLength;
    req.wValue = wValue;
    return transmit_usb_buffer(&req, sizeof(struct usb_device_request), true, outBuf, outLen, false);
}

transmission_response_t send_std_request(uint8_t request, uint8_t direction, uint8_t recipient, uint16_t wIndex, uint16_t wLength, uint16_t wValue, void *outBuf, size_t outLen)
{
    return transmit_setup(USB_REQ_TYPE_STANDARD | recipient | direction, request, wIndex, wLength, wValue, outBuf, outLen);
}

void send_dfu_request(dfu_request_type_t request, uint8_t direction)
{
    transmit_setup(USB_REQ_TYPE_CLASS | USB_REQ_RECIPIENT_INTERFACE | direction, request, 0, 0, 0, NULL, -1);
}

void send_get_status()
{
    send_dfu_request(DFU_GETSTATUS, USB_REQ_DEVICE2HOST);
}

void send_abort()
{
    send_dfu_request(DFU_ABORT, USB_REQ_HOST2DEVICE);
}

void send_clr_status()
{
    send_dfu_request(DFU_CLR_STATUS, USB_REQ_HOST2DEVICE);
}

transmission_response_t send_get_descriptor(uint8_t descType, uint8_t descIdx, uint16_t langId, void *outBuf, size_t outLen)
{
    return send_std_request(USB_REQ_GET_DESCRIPTOR, USB_REQ_DEVICE2HOST, USB_REQ_RECIPIENT_DEVICE, langId, outLen, (descType << 8) | descIdx, outBuf, outLen);
}

transmission_response_t send_get_string_descriptor(uint8_t descIdx, uint16_t langId, char *outBuf, size_t outLen)
{
    struct usb_string_descriptor* str_desc;
    size_t str_desc_len = sizeof(struct usb_string_descriptor) - 2 + 2*outLen;
    str_desc = malloc(str_desc_len);
    transmission_response_t res = send_get_descriptor(USB_DT_STRING, descIdx, langId, str_desc, str_desc_len);
    size_t str_len = (str_desc->bLength + 2 - sizeof(struct usb_string_descriptor)) / 2;
    size_t max_size = str_len;
    if (max_size > outLen) max_size = outLen;
    if (res == OK || res == OUT_TRUNC)
    {
        uint16_t* wData = (uint16_t*)str_desc->wData;
        for (int i = 0; i < max_size; i++) {
            outBuf[i] = (char)wData[i];
        }
    }

    return res;
}

void send_event(usb_event_t event)
{
    pthread_mutex_lock(&usb_mgr.ready_lock);

    pthread_mutex_unlock(&usb_mgr.ready_lock);
}