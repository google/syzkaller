// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

// NetBSD-specific implementation of syz_usb_* pseudo-syscalls.

#include <dev/usb/usb.h>
#include <dev/usb/usbhid.h>
#include <dev/usb/vhci.h>
#include <fcntl.h>
#include <sys/ioctl.h>

// Redefinitions to match the linux types used in common_usb.h.

struct usb_endpoint_descriptor {
	uint8 bLength;
	uint8 bDescriptorType;
	uint8 bEndpointAddress;
	uint8 bmAttributes;
	uint16 wMaxPacketSize;
	uint8 bInterval;
	uint8 bRefresh;
	uint8 bSynchAddress;
} __attribute__((packed));

struct usb_device_descriptor {
	uint8 bLength;
	uint8 bDescriptorType;
	uint16 bcdUSB;
	uint8 bDeviceClass;
	uint8 bDeviceSubClass;
	uint8 bDeviceProtocol;
	uint8 bMaxPacketSize0;
	uint16 idVendor;
	uint16 idProduct;
	uint16 bcdDevice;
	uint8 iManufacturer;
	uint8 iProduct;
	uint8 iSerialNumber;
	uint8 bNumConfigurations;
} __attribute__((packed));

struct usb_config_descriptor {
	uint8 bLength;
	uint8 bDescriptorType;

	uint16 wTotalLength;
	uint8 bNumInterfaces;
	uint8 bConfigurationValue;
	uint8 iConfiguration;
	uint8 bmAttributes;
	uint8 bMaxPower;
} __attribute__((packed));

struct usb_interface_descriptor {
	uint8 bLength;
	uint8 bDescriptorType;
	uint8 bInterfaceNumber;
	uint8 bAlternateSetting;
	uint8 bNumEndpoints;
	uint8 bInterfaceClass;
	uint8 bInterfaceSubClass;
	uint8 bInterfaceProtocol;
	uint8 iInterface;
} __attribute__((packed));

struct usb_ctrlrequest {
	uint8 bRequestType;
	uint8 bRequest;
	uint16 wValue;
	uint16 wIndex;
	uint16 wLength;
} __attribute__((packed));

struct usb_qualifier_descriptor {
	uint8 bLength;
	uint8 bDescriptorType;
	uint16 bcdUSB;
	uint8 bDeviceClass;
	uint8 bDeviceSubClass;
	uint8 bDeviceProtocol;
	uint8 bMaxPacketSize0;
	uint8 bNumConfigurations;
	uint8 bRESERVED;
} __attribute__((packed));

#define USB_TYPE_MASK (0x03 << 5)
#define USB_TYPE_STANDARD (0x00 << 5)
#define USB_TYPE_CLASS (0x01 << 5)
#define USB_TYPE_VENDOR (0x02 << 5)
#define USB_TYPE_RESERVED (0x03 << 5)

#define USB_DT_DEVICE 0x01
#define USB_DT_CONFIG 0x02
#define USB_DT_STRING 0x03
#define USB_DT_INTERFACE 0x04
#define USB_DT_ENDPOINT 0x05
#define USB_DT_DEVICE_QUALIFIER 0x06
#define USB_DT_OTHER_SPEED_CONFIG 0x07
#define USB_DT_INTERFACE_POWER 0x08
#define USB_DT_OTG 0x09
#define USB_DT_DEBUG 0x0a
#define USB_DT_INTERFACE_ASSOCIATION 0x0b
#define USB_DT_SECURITY 0x0c
#define USB_DT_KEY 0x0d
#define USB_DT_ENCRYPTION_TYPE 0x0e
#define USB_DT_BOS 0x0f
#define USB_DT_DEVICE_CAPABILITY 0x10
#define USB_DT_WIRELESS_ENDPOINT_COMP 0x11
#define USB_DT_WIRE_ADAPTER 0x21
#define USB_DT_RPIPE 0x22
#define USB_DT_CS_RADIO_CONTROL 0x23
#define USB_DT_PIPE_USAGE 0x24
#define USB_DT_SS_ENDPOINT_COMP 0x30
#define USB_DT_SSP_ISOC_ENDPOINT_COMP 0x31

#define USB_REQ_GET_STATUS 0x00
#define USB_REQ_CLEAR_FEATURE 0x01
#define USB_REQ_SET_FEATURE 0x03
#define USB_REQ_SET_ADDRESS 0x05
#define USB_REQ_GET_DESCRIPTOR 0x06
#define USB_REQ_SET_DESCRIPTOR 0x07
#define USB_REQ_GET_CONFIGURATION 0x08
#define USB_REQ_SET_CONFIGURATION 0x09
#define USB_REQ_GET_INTERFACE 0x0A
#define USB_REQ_SET_INTERFACE 0x0B
#define USB_REQ_SYNCH_FRAME 0x0C
#define USB_REQ_SET_SEL 0x30
#define USB_REQ_SET_ISOCH_DELAY 0x31

#define USB_REQ_SET_ENCRYPTION 0x0D
#define USB_REQ_GET_ENCRYPTION 0x0E
#define USB_REQ_RPIPE_ABORT 0x0E
#define USB_REQ_SET_HANDSHAKE 0x0F
#define USB_REQ_RPIPE_RESET 0x0F
#define USB_REQ_GET_HANDSHAKE 0x10
#define USB_REQ_SET_CONNECTION 0x11
#define USB_REQ_SET_SECURITY_DATA 0x12
#define USB_REQ_GET_SECURITY_DATA 0x13
#define USB_REQ_SET_WUSB_DATA 0x14
#define USB_REQ_LOOPBACK_DATA_WRITE 0x15
#define USB_REQ_LOOPBACK_DATA_READ 0x16
#define USB_REQ_SET_INTERFACE_DS 0x17

#define USB_REQ_GET_PARTNER_PDO 20
#define USB_REQ_GET_BATTERY_STATUS 21
#define USB_REQ_SET_PDO 22
#define USB_REQ_GET_VDM 23
#define USB_REQ_SEND_VDM 24

#include "common_usb.h"

static int vhci_open(void)
{
	char path[1024];

	snprintf(path, sizeof(path), "/dev/vhci%llu", procid);

	return open(path, O_RDWR);
}

static int vhci_setport(int fd, u_int port)
{
	struct vhci_ioc_set_port args;

	args.port = port;
	return ioctl(fd, VHCI_IOC_SET_PORT, &args);
}

static int vhci_usb_attach(int fd)
{
	return ioctl(fd, VHCI_IOC_USB_ATTACH, NULL);
}

static int vhci_usb_recv(int fd, void* buf, size_t size)
{
	uint8* ptr = (uint8*)buf;

	while (1) {
		ssize_t done = read(fd, ptr, size);
		if (done < 0)
			return -1;
		if ((size_t)done == size)
			return 0;
		size -= done;
		ptr += done;
	}
}

static int vhci_usb_send(int fd, void* buf, size_t size)
{
	uint8* ptr = (uint8*)buf;

	while (1) {
		ssize_t done = write(fd, ptr, size);
		if (done <= 0)
			return -1;
		if ((size_t)done == size)
			return 0;
		size -= done;
		ptr += done;
	}
}

static volatile long syz_usb_connect_impl(int fd, uint64 speed, uint64 dev_len,
					  const char* dev, const struct vusb_connect_descriptors* descs,
					  lookup_connect_out_response_t lookup_connect_response_out)
{
	struct usb_device_index* index = add_usb_index(fd, dev, dev_len);
	if (!index) {
		debug("syz_usb_connect: add_usb_index failed\n");
		return -1;
	}
	debug("syz_usb_connect: add_usb_index success\n");

#if USB_DEBUG
	analyze_usb_device(index);
#endif

	int rv = vhci_setport(fd, 1);
	if (rv != 0) {
		fail("syz_usb_connect: vhci_setport failed with %d", errno);
	}

	rv = vhci_usb_attach(fd);
	if (rv != 0) {
		debug("syz_usb_connect: vhci_usb_attach failed with %d\n", rv);
		return -1;
	}
	debug("syz_usb_connect: vhci_usb_attach success\n");

	bool done = false;
	while (!done) {
		vhci_request_t req;

		rv = vhci_usb_recv(fd, &req, sizeof(req));
		if (rv != 0) {
			debug("syz_usb_connect: vhci_usb_recv failed with %d\n", errno);
			return -1;
		}
		if (req.type != VHCI_REQ_CTRL) {
			debug("syz_usb_connect: received non-control transfer\n");
			return -1;
		}

		debug("syz_usb_connect: bReqType: 0x%x (%s), bReq: 0x%x, wVal: 0x%x, wIdx: 0x%x, wLen: %d\n",
		      req.u.ctrl.bmRequestType, (req.u.ctrl.bmRequestType & UE_DIR_IN) ? "IN" : "OUT",
		      req.u.ctrl.bRequest, UGETW(req.u.ctrl.wValue), UGETW(req.u.ctrl.wIndex), UGETW(req.u.ctrl.wLength));

#if USB_DEBUG
		analyze_control_request(fd, &req.u.ctrl);
#endif

		char* response_data = NULL;
		uint32 response_length = 0;
		char data[4096];

		if (req.u.ctrl.bmRequestType & UE_DIR_IN) {
			if (!lookup_connect_response_in(fd, descs, (const struct usb_ctrlrequest*)&req.u.ctrl, &response_data, &response_length)) {
				debug("syz_usb_connect: unknown control IN request\n");
				return -1;
			}
		} else {
			if (!lookup_connect_response_out(fd, descs, (const struct usb_ctrlrequest*)&req.u.ctrl, &done)) {
				debug("syz_usb_connect: unknown control OUT request\n");
				return -1;
			}
			response_data = NULL;
			response_length = UGETW(req.u.ctrl.wLength);
		}

		if ((req.u.ctrl.bmRequestType & USB_TYPE_MASK) == USB_TYPE_STANDARD &&
		    req.u.ctrl.bRequest == USB_REQ_SET_CONFIGURATION) {
			// TODO: possibly revisit.
		}

		if (response_length > sizeof(data))
			response_length = 0;
		if ((uint32)UGETW(req.u.ctrl.wLength) < response_length)
			response_length = UGETW(req.u.ctrl.wLength);

		if (response_data)
			memcpy(data, response_data, response_length);
		else
			memset(data, 0, response_length);

		if (req.u.ctrl.bmRequestType & UE_DIR_IN) {
			debug("syz_usb_connect: writing %d bytes\n", response_length);
			if (response_length > 0) {
				vhci_response_t res;
				res.size = response_length;
				rv = vhci_usb_send(fd, &res, sizeof(res));
				if (rv == 0)
					rv = vhci_usb_send(fd, data, response_length);
			}
		} else {
			rv = vhci_usb_recv(fd, data, response_length);
			debug("syz_usb_connect: read %d bytes\n", response_length);
			debug_dump_data(&data[0], response_length);
		}
		if (rv < 0) {
			debug("syz_usb_connect: usb_raw_ep0_read/write failed with %d\n", rv);
			return -1;
		}
	}

	sleep_ms(200);
	debug("syz_usb_connect: configured\n");
	return fd;
}

#if SYZ_EXECUTOR || __NR_syz_usb_connect
static volatile long syz_usb_connect(volatile long a0, volatile long a1,
				     volatile long a2, volatile long a3)
{
	uint64 speed = a0;
	uint64 dev_len = a1;
	const char* dev = (const char*)a2;
	const struct vusb_connect_descriptors* descs = (const struct vusb_connect_descriptors*)a3;

	debug("syz_usb_connect: dev: %p\n", dev);
	if (!dev) {
		debug("syz_usb_connect: dev is null\n");
		return -1;
	}

	debug("syz_usb_connect: device data:\n");
	debug_dump_data(dev, dev_len);

	int fd = vhci_open();
	if (fd < 0) {
		fail("syz_usb_connect: vhci_open failed with %d", errno);
	}
	long res = syz_usb_connect_impl(fd, speed, dev_len, dev, descs, &lookup_connect_response_out_generic);
	close(fd);
	return res;
}
#endif // SYZ_EXECUTOR || __NR_syz_usb_connect

#if SYZ_EXECUTOR || __NR_syz_usb_disconnect
static volatile long syz_usb_disconnect(volatile long a0)
{
	int fd = a0;

	int rv = close(fd);

	sleep_ms(200);

	return rv;
}
#endif // SYZ_EXECUTOR || __NR_syz_usb_disconnect
