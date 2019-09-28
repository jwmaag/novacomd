#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <libusb.h>
#include <assert.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>

#include <transport_usb.h>
#include <platform.h>
#include <novacom.h>
#include <debug.h>
#include <log.h>
#include <sys/queue.h>

#include "../novacom/mux.h"
#include "device_list.h"

#define LOCAL_TRACE 0
#define USBDEVFS_IOCTL_TIMEOUT  2000

// novacom_usb_handle_t
typedef struct {
	libusb_context *ctx;
	libusb_device *dev;
	libusb_device_handle *hdl;

	novacom_usbll_handle_t usbll_handle;

	bool shutdown;
	platform_event_t tx_startup_event;		/* event to block tx thread until any packet received on rx side*/
	int tx_startup_wait;					/* flag to indicate that we are blocked on tx */
	platform_event_t tx_shutdown_event;		/* event to indicate tx thread shutdown */

	int rxep;
	int txep;
	int rx_timeout;
	int tx_timeout;
	int busnum;
	int devnum;
	const char *devtype;
	int iface;
} novacom_usb_handle_t;
  
typedef struct recovery_entry_s {
        transport_recovery_token_t      *t_token;               /* transport recovery token */
        int timeout;                                                            /* timout value */

        TAILQ_ENTRY(recovery_entry_s) entries;          /* holds pointers to prev, next entries */
} recovery_entry_t;

#define TRACE_ZERO_LEN_PACKETS 0
#define FAULTY_TX 0
#define MAX_MTU 16384


volatile int novacom_shutdown=0;
TAILQ_HEAD(recovery_queue_s, recovery_entry_s)  t_recovery_queue;
static platform_thread_t findandattach_thread;
static platform_mutex_t recovery_lock;

static void* novacom_usb_findandattach_thread(void*);
//static void* novacom_usb_tx_thread(void*);
//static void* novacom_usb_rx_thread(void*);

int
novacom_usb_transport_init(void)
{	
	return(0);
}

int
novacom_usb_transport_start(void)
{
	novacom_shutdown = 0;
	platform_create_thread(&findandattach_thread, &novacom_usb_findandattach_thread, NULL);
	platform_mutex_init(&recovery_lock);
	return (0);
}

int
novacom_usb_transport_stop(void)
{
	novacom_shutdown = 1;
	platform_waitfor_thread(findandattach_thread);
	platform_mutex_destroy(&recovery_lock);
	return (0);
}

int
novacom_usb_transport_deviceonline(char *nduid)
{
	usbrecords_remove(nduid);
	return (0);
}

static int
novacom_usb_read(novacom_usb_handle_t *handle, void *buf, size_t len, int *xfer)
{
	int rc;
	rc = libusb_bulk_transfer(handle->hdl, handle->rxep, buf, len, xfer, handle->rx_timeout);
	return (rc);

}

static int
novacom_usb_write(novacom_usb_handle_t *handle, void *buf, size_t len, int *xfer)
{
	int rc;
	rc = libusb_bulk_transfer(handle->hdl, handle->txep, buf, len, xfer, handle->tx_timeout);
	return (rc);
}

static int
novacom_usb_close(novacom_usb_handle_t *usb_handle)
{
	libusb_release_interface(usb_handle->hdl, usb_handle->iface);
	libusb_close(usb_handle->hdl);
	usb_handle->hdl = NULL;

	return (0);
}

static int
novacom_usb_find_endpoints(libusb_device *dev, libusb_device_handle *hdl, int eps[2], int *iface)
{
	libusb_device_descriptor d;
	libusb_config_descriptor *cfg;
	struct libusb_interface interface;
	struct libusb_interface_descriptor setting;
	int rc;
	size_t i, j;

	libusb_get_device_descriptor(dev, &d);
	libusb_get_active_config_descriptor(dev, &cfg);

	for(i = 0; i < cfg->bNumInterfaces; i++ ) {
		interface = cfg->interface[i];
		for(j = 0; j < interface.num_altsetting; j++) {
			setting = interface.altsetting[j];
			if(setting.bInterfaceClass == LIBUSB_CLASS_VENDOR_SPEC &&
				setting.bInterfaceSubClass == 0x47 &&
				setting.bInterfaceProtocol == 0x11) {
			
				eps[0] = eps[1] = 0;
				if (setting.endpoint[0].bEndpointAddress & 0x80)
					eps[0] = setting.endpoint[0].bEndpointAddress;
				if ((setting.endpoint[1].bEndpointAddress & 0x80) == 0 )
					eps[1] = setting.endpoint[1].bEndpointAddress;

				if(eps[0] == 0 || eps[1] == 0)
					continue;

				rc = libusb_claim_interface(hdl, i);
				if (rc)
					return -1;
				
				*iface = i;
				return (0);
			}
		}	
	}
	return -1;
}

/* Find the device and open it returning our own handle 
 */
static novacom_usb_handle_t*
novacom_usb_open(libusb_context *ctx)
{
	novacom_usb_handle_t *nhdl;
	libusb_device **list, *dev = NULL, *found = NULL;
	libusb_device_handle *hdl;
	libusb_device_descriptor d;
	int iface, ep[2];
	size_t n, i, j;

	nhdl = NULL;
	n = libusb_get_device_list(ctx, &list);

	// loop over devices
	for (i = 0; i < n; i++) {
		dev = list[i];
		libusb_get_device_descriptor(dev, &d);
		
		//compare with the internal list of supprted devices
		for (j = 0; usbid_list[j].name; j++) {
			if ((d.idVendor == usbid_list[j].vendor) && 
				(d.idProduct == usbid_list[j].product)) {

				found = libusb_ref_device(dev);

				if (libusb_open(dev, &hdl) != 0)
					continue;
				
				
				if (novacom_usb_find_endpoints(dev, hdl, ep, &iface) != 0)
					continue;
				

				nhdl = platform_calloc(sizeof(novacom_usb_handle_t));
				if(!nhdl) {
					libusb_close(hdl);
					return (NULL);
				}
				
				nhdl->ctx = ctx;
				nhdl->dev = dev;
				nhdl->hdl = hdl;
				nhdl->iface = iface;
				nhdl->rxep = ep[0];
				nhdl->txep = ep[1];
				nhdl->devtype = usbid_list[j].name;	
				nhdl->busnum = libusb_get_bus_number(dev);
				nhdl->devnum = libusb_get_device_address(dev);
				
				// return our handle
				goto exit;
			}
		}
	}
	
exit:
	libusb_free_device_list(list, 1);
	return nhdl;
}

// thread main
static void*
novacom_usb_tx_thread(void *arg)
{
	novacom_usb_handle_t *handle = (novacom_usb_handle_t *)arg;
        int rc;
	int transferred;
        struct novacom_tx_packet packet;
        char *buf;

        buf = platform_calloc(MAX_MTU);
        platform_assert(buf != NULL);

        LTRACEF("start::wait for startup event: %p\n", handle);
        platform_event_wait(&handle->tx_startup_event);   //why waiting rx for starting ???
        handle->tx_startup_wait = 0;                      //change status to started
        LTRACEF("start::startup event received, continue: %p\n", handle);

        handle->tx_timeout = novacom_usbll_get_timeout(handle->usbll_handle);
        while (!novacom_shutdown && !handle->shutdown) {
                // see if we have something to send
		packet.len = novacom_usbll_get_mtu(handle->usbll_handle);
                packet.buf = buf;
                if (novacom_usbll_prepare_tx_packet(handle->usbll_handle, &packet, 100) != TX_NO_PACKET) {
                        // write a block back
#if FAULTY_TX
                        if (rand() < (RAND_MAX / 10)) {
                                TRACEF("dropped tx packet\n");
                        } else {
#endif
                                rc = novacom_usb_write(handle, packet.buf, packet.len, &transferred);
                                if (rc != 0) {
                                        platform_time_t st;
                                        platform_time_t et;
                                        int time_used = 0;
                                        unsigned int count = 0;

                                        TRACEL(LOG_ALWAYS, "usbll(%08x) error writing packet, result(%d), errno %d\n", 
						novacom_usbll_getuid(handle->usbll_handle), rc, errno);

                                        platform_get_time(&st);
                                        while (rc != 0 && !handle->shutdown) { //shutdown asap
                                                platform_get_time(&et);
                                                if (platform_delta_time_msecs(&st, &et) >= g_usbio_retry_timeout) {
							handle->shutdown = true;
                                                        break;
                                                }
                                                if (g_usbio_retry_delay > 0) {
                                                        if ((g_usbio_retry_timeout-time_used) >= g_usbio_retry_delay) {
                                                                usleep(g_usbio_retry_delay * 1000);
                                                                time_used += g_usbio_retry_delay;
                                                        }
                                                        else {
                                                                usleep((g_usbio_retry_timeout - time_used) * 1000);
                                                                time_used = g_usbio_retry_timeout;
                                                        }
                                                }
                                                rc = novacom_usb_write(handle, packet.buf, packet.len, &transferred);
                                                count++;

                                        }

                                        TRACEL(LOG_ALWAYS, 
						"usbll(%08x) writing packet, writes(%ld), duration(%dms), result(%d), last_errno %ld\n", 
						novacom_usbll_getuid(handle->usbll_handle), count, 
						platform_delta_time_msecs(&st, &et), rc, errno);

                                        count = 0;
                                }
                                if (rc == 0) {
                                        TRACEF/*LOG_PRINTF*/("usbll(%08x) wrote tx packet len=%d\n", novacom_usbll_getuid(handle->usbll_handle), transferred);
                                }

#if FAULTY_TX
                        }
#endif
                }
        }

        LTRACEF("shutting down handle %p\n", handle);

        platform_event_signal(&handle->tx_shutdown_event);

        platform_free(buf);

        return NULL;
}

static void*
novacom_usb_rx_thread(void *arg)
{
	novacom_usb_handle_t *handle = (novacom_usb_handle_t *)arg;
	transport_recovery_token_t *rec_token = NULL;					///< recovery token
	int rc;
	int packet_type;
	char *buf;
	int sniff = 1;
	int transferred;

	buf = platform_calloc(MAX_MTU);
	platform_assert(buf != NULL);

	LTRACEF("start, handle %p\n", handle);

	handle->rx_timeout = novacom_usbll_get_timeout(handle->usbll_handle);
	while (!novacom_shutdown && !handle->shutdown) {
		platform_time_t st;
		int time_used;
		// read a block from the pmux
		rc = novacom_usb_read(handle, buf, novacom_usbll_get_mtu(handle->usbll_handle), &transferred);
		platform_get_time(&st);
		time_used = 0;

		// rc == 0 is a success. 
		if (rc != 0) {
			platform_time_t et;
			unsigned int count = 0;
			TRACEL(LOG_ALWAYS, "%s:%d -- usbll(%08x) error: reading packet, result(%d), errno %d\n", __FUNCTION__, __LINE__, novacom_usbll_getuid(handle->usbll_handle), rc, errno);
			while (rc != 0 && !handle->shutdown) { //shutdown asap
				platform_get_time(&et);
				if (platform_delta_time_msecs(&st, &et) >= g_usbio_retry_timeout) {
					handle->shutdown = true;
					break;
				}
				if (g_usbio_retry_delay > 0) {
					if ((g_usbio_retry_timeout-time_used) >= g_usbio_retry_delay) {
						usleep(g_usbio_retry_delay * 1000);
						time_used += g_usbio_retry_delay;
					}
					else {
						usleep((g_usbio_retry_timeout - time_used) * 1000);
						time_used = g_usbio_retry_timeout;
					}
				}
				rc = novacom_usb_read(handle, buf, novacom_usbll_get_mtu(handle->usbll_handle), &transferred);
				count++;

			}
		    TRACEL(LOG_ALWAYS, "%s:%d -- usbll(%08x) reading packet, reads(%ld), duration(%dms), result(%d), last_errno %ld\n",  __FUNCTION__, __LINE__, novacom_usbll_getuid(handle->usbll_handle), count, platform_delta_time_msecs(&st, &et), rc, errno);
 		    count = 0;

		}

		/* sniff */
		if(sniff) {
			uint32_t uid = ((handle->busnum & 0x0FFFF) << 16) | (handle->devnum & 0x0FFFF);
			transport_recovery_token_t sniff_token;
			int ret;

			/* generate token from packet */
			ret = novacom_usbll_generate_recovery_token(buf, rc, &sniff_token);
			if(ret == -1) {
				TRACEL(LOG_ERROR, "%s:%d -- Used out system resouce, exit now !!!\n", __FUNCTION__, __LINE__);
				abort();
			}
			/* check queue for saved connections */
			ret = usbrecords_find(&sniff_token);
			/* free interface recovery token */
			platform_free(sniff_token.token);
			/* check result: create new handle, or recover */
			if(ret) {
				LTRACEF("Unable to recover(%d)\n", ret);
				handle->usbll_handle = novacom_usbll_create(handle->devtype, MAX_MTU, 0, USBDEVFS_IOCTL_TIMEOUT);
			} else {
				TRACEL(LOG_ERROR, "Recovered record...\n");
				handle->usbll_handle = sniff_token.user_data;
			}
			/* update uid */
			novacom_usbll_setuid(handle->usbll_handle, uid);
			handle->rx_timeout = novacom_usbll_get_timeout(handle->usbll_handle);
			handle->tx_timeout = novacom_usbll_get_timeout(handle->usbll_handle);
			sniff = 0;
		}
		/* process */
		packet_type = PACKET_TYPE_NULL;
		if (transferred >= 0) {
			// what is the actual length of the packet? how much was read?
			
			// process it
			packet_type = novacom_usbll_process_packet(handle->usbll_handle, buf, transferred);
			if (packet_type == PACKET_TYPE_BADPACKET) {
				platform_time_t et;
				TRACEF("received bad packet\n");
				platform_get_time(&et);
				if (platform_delta_time_msecs(&st, &et) >= g_usbio_retry_timeout) {
					handle->shutdown = true;
					break;
				}
				if (g_usbio_retry_delay > 0) {
					if ((g_usbio_retry_timeout-time_used) >= g_usbio_retry_delay) {
						usleep(g_usbio_retry_delay * 1000);
						time_used += g_usbio_retry_delay;
					}
					else {
						usleep((g_usbio_retry_timeout - time_used) * 1000);
						time_used = g_usbio_retry_timeout;
					}
				}
				///handle->shutdown = true;
				///break;
			} else if(handle->tx_startup_wait) {
				platform_event_signal(&handle->tx_startup_event);
			}
		} else {
#if TRACE_ZERO_LEN_PACKETS
			log_printf(LOG_TRACE, "RX zero len\n");
#endif
		}
	}

	LTRACEF("shutting down handle %p\n", handle);

	/* wake up tx thread (if still waits for startup) */
	if(handle->tx_startup_wait) {
		LTRACEF("wake up tx thread\n");
		platform_event_signal(&handle->tx_startup_event);
	}

	/* wait for the tx thread to exit */
	LTRACEF("waiting on tx thread\n");
	platform_event_wait(&handle->tx_shutdown_event);

	/* RX thread is responsible for cleaning up */
	LTRACEF("cleaning up handle %p\n", handle);

	/* grab recovery token if available */
	if(handle->usbll_handle) {
		rc = -1;
		rec_token = platform_calloc(sizeof(transport_recovery_token_t));
		if(rec_token) {
			snprintf(rec_token->nduid, sizeof(rec_token->nduid), "%s", novacom_usbll_get_nduid(handle->usbll_handle));
			rc = novacom_usbll_get_recovery_token(handle->usbll_handle, rec_token);
			if(rc != -1) {
				rc = usbrecords_add(rec_token);
			} else {
				LTRACEF("unable to recovery token!!!\n");
			}
		}
		/* error: free memory, destroy device */
		if(rc == -1) { //we should never go here.
			novacom_usbll_destroy(handle->usbll_handle);
			platform_free(rec_token);
		}
	}

	novacom_usb_close(handle);
	platform_event_destroy(&handle->tx_startup_event);
	platform_event_destroy(&handle->tx_shutdown_event);
	platform_free(handle);
	platform_free(buf);

	return NULL;
}

static void*
novacom_usb_findandattach_thread(void *arg)
{
	libusb_context *ctx;
	novacom_usb_handle_t *usb;
	
	libusb_init(&ctx);

	// not sure what this is for since libusb does this for
	// us i believe
	while(!novacom_shutdown){
		usb = novacom_usb_open(ctx);
		if (usb) {
			usb->shutdown = false;
			TRACEF("usb_handle 0x%08x, bus=%03d dev=%03d\n", usb->usbll_handle, usb->busnum, usb->devnum);
                        platform_event_create(&usb->tx_startup_event);
                        platform_event_unsignal(&usb->tx_startup_event);
                        usb->tx_startup_wait = 1;
                        platform_event_create(&usb->tx_shutdown_event);
                        platform_event_unsignal(&usb->tx_shutdown_event);

                        platform_create_thread(NULL, &novacom_usb_rx_thread, (void *)usb);
                        platform_create_thread(NULL, &novacom_usb_tx_thread, (void *)usb);	
		}
		if (!novacom_shutdown) {
			sleep(1);
			(void) usbrecords_update(1);
		}
	}
	
	usbrecords_update(TRANSPORT_RECOVERY_TIMEOUT);
	libusb_exit(ctx);
	return (NULL);
}


