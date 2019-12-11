// +build

// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <linux/types.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include <linux/hid.h>
#include <linux/usb/ch9.h>

/*----------------------------------------------------------------------*/

struct hid_class_descriptor {
	__u8  bDescriptorType;
	__le16 wDescriptorLength;
} __attribute__ ((packed));

struct hid_descriptor {
	__u8  bLength;
	__u8  bDescriptorType;
	__le16 bcdHID;
	__u8  bCountryCode;
	__u8  bNumDescriptors;

	struct hid_class_descriptor desc[1];
} __attribute__ ((packed));

/*----------------------------------------------------------------------*/

#define UDC_NAME_LENGTH_MAX 128

struct usb_raw_init {
	__u8 driver_name[UDC_NAME_LENGTH_MAX];
	__u8 device_name[UDC_NAME_LENGTH_MAX];
	__u8 speed;
};

enum usb_raw_event_type {
	USB_RAW_EVENT_INVALID,
	USB_RAW_EVENT_CONNECT,
	USB_RAW_EVENT_CONTROL,
};

struct usb_raw_event {
	__u32		type;
	__u32		length;
	__u8		data[0];
};

struct usb_raw_ep_io {
	__u16		ep;
	__u16		flags;
	__u32		length;
	__u8		data[0];
};

#define USB_RAW_IOCTL_INIT		_IOW('U', 0, struct usb_raw_init)
#define USB_RAW_IOCTL_RUN		_IO('U', 1)
#define USB_RAW_IOCTL_EVENT_FETCH	_IOR('U', 2, struct usb_raw_event)
#define USB_RAW_IOCTL_EP0_WRITE		_IOW('U', 3, struct usb_raw_ep_io)
#define USB_RAW_IOCTL_EP0_READ		_IOWR('U', 4, struct usb_raw_ep_io)
#define USB_RAW_IOCTL_EP_ENABLE		_IOW('U', 5, struct usb_endpoint_descriptor)
#define USB_RAW_IOCTL_EP_DISABLE	_IOW('U', 6, __u32)
#define USB_RAW_IOCTL_EP_WRITE		_IOW('U', 7, struct usb_raw_ep_io)
#define USB_RAW_IOCTL_EP_READ		_IOWR('U', 8, struct usb_raw_ep_io)
#define USB_RAW_IOCTL_CONFIGURE		_IO('U', 9)
#define USB_RAW_IOCTL_VBUS_DRAW		_IOW('U', 10, __u32)

/*----------------------------------------------------------------------*/

int usb_raw_open() {
	int fd = open("/dev/raw-gadget", O_RDWR);
	if (fd < 0) {
		perror("open()");
		exit(EXIT_FAILURE);
	}
	return fd;
}

void usb_raw_init(int fd, enum usb_device_speed speed) {
	struct usb_raw_init arg;
	strcpy(&arg.driver_name[0], "dummy_udc");
	strcpy(&arg.device_name[0], "dummy_udc.0");
	arg.speed = speed;
	int rv = ioctl(fd, USB_RAW_IOCTL_INIT, &arg);
	if (rv < 0) {
		perror("ioctl(USB_RAW_IOCTL_INIT)");
		exit(EXIT_FAILURE);
	}
}

void usb_raw_run(int fd) {
	int rv = ioctl(fd, USB_RAW_IOCTL_RUN, 0);
	if (rv < 0) {
		perror("ioctl(USB_RAW_IOCTL_RUN)");
		exit(EXIT_FAILURE);
	}
}

void USB_RAW_EVENT_fetch(int fd, struct usb_raw_event *event) {
	int rv = ioctl(fd, USB_RAW_IOCTL_EVENT_FETCH, event);
	if (rv < 0) {
		perror("ioctl(USB_RAW_IOCTL_EVENT_FETCH)");
		exit(EXIT_FAILURE);
	}
}

void usb_raw_ep0_read(int fd, struct usb_raw_ep_io *io) {
	int rv = ioctl(fd, USB_RAW_IOCTL_EP0_READ, io);
	if (rv < 0) {
		perror("ioctl(USB_RAW_IOCTL_EP0_READ)");
		exit(EXIT_FAILURE);
	}
}

void usb_raw_ep0_write(int fd, struct usb_raw_ep_io *io) {
	int rv = ioctl(fd, USB_RAW_IOCTL_EP0_WRITE, io);
	if (rv < 0) {
		perror("ioctl(USB_RAW_IOCTL_EP0_WRITE)");
		exit(EXIT_FAILURE);
	}
}

int usb_raw_ep_enable(int fd, struct usb_endpoint_descriptor *desc) {
	int rv = ioctl(fd, USB_RAW_IOCTL_EP_ENABLE, desc);
	if (rv < 0) {
		perror("ioctl(USB_RAW_IOCTL_EP_ENABLE)");
		exit(EXIT_FAILURE);
	}
	return rv;
}

int usb_raw_ep_write(int fd, struct usb_raw_ep_io *io) {
	int rv = ioctl(fd, USB_RAW_IOCTL_EP_WRITE, io);
	if (rv < 0) {
		perror("ioctl(USB_RAW_IOCTL_EP_WRITE)");
		exit(EXIT_FAILURE);
	}
	return rv;
}

void usb_raw_configure(int fd) {
	int rv = ioctl(fd, USB_RAW_IOCTL_CONFIGURE, 0);
	if (rv < 0) {
		perror("ioctl(USB_RAW_IOCTL_CONFIGURED)");
		exit(EXIT_FAILURE);
	}
}

void usb_raw_vbus_draw(int fd, uint32_t power) {
	int rv = ioctl(fd, USB_RAW_IOCTL_VBUS_DRAW, power);
	if (rv < 0) {
		perror("ioctl(USB_RAW_IOCTL_VBUS_DRAW)");
		exit(EXIT_FAILURE);
	}
}

/*----------------------------------------------------------------------*/

#define MAX_PACKET_SIZE	64

#define USB_VENDOR	0x046d
#define USB_PRODUCT	0xc312 

#define STRING_ID_MANUFACTURER	0
#define STRING_ID_PRODUCT	1
#define STRING_ID_SERIAL	2
#define STRING_ID_CONFIG	3
#define STRING_ID_INTERFACE	4

struct usb_device_descriptor usb_device = {
	.bLength =		USB_DT_DEVICE_SIZE,
	.bDescriptorType =	USB_DT_DEVICE,
	.bcdUSB =		__constant_cpu_to_le16(0x0200),
	.bDeviceClass =		0,
	.bDeviceSubClass =	0,
	.bDeviceProtocol =	0,
	.bMaxPacketSize0 =	MAX_PACKET_SIZE,
	.idVendor =		__constant_cpu_to_le16(USB_VENDOR),
	.idProduct =		__constant_cpu_to_le16(USB_PRODUCT),
	.bcdDevice =		0,
	.iManufacturer =	STRING_ID_MANUFACTURER,
	.iProduct =		STRING_ID_PRODUCT,
	.iSerialNumber =	STRING_ID_SERIAL,
	.bNumConfigurations =	1,
};

struct usb_qualifier_descriptor usb_qualifier = {
	.bLength =		sizeof(struct usb_qualifier_descriptor),
	.bDescriptorType =	USB_DT_DEVICE_QUALIFIER,
	.bcdUSB =		__constant_cpu_to_le16(0x0200),
	.bDeviceClass =		0,
	.bDeviceSubClass =	0,
	.bDeviceProtocol =	0,
	.bMaxPacketSize0 =	MAX_PACKET_SIZE,
	.bNumConfigurations =	1,
	.bRESERVED =		0,
};

struct usb_config_descriptor usb_config = {
	.bLength =		USB_DT_CONFIG_SIZE,
	.bDescriptorType =	USB_DT_CONFIG,
	.wTotalLength =		0,  // computed later
	.bNumInterfaces =	1,
	.bConfigurationValue =	1,
	.iConfiguration = 	STRING_ID_CONFIG,
	.bmAttributes =		USB_CONFIG_ATT_ONE | USB_CONFIG_ATT_SELFPOWER,
	.bMaxPower =		0x32,
};

struct usb_interface_descriptor usb_interface = {
	.bLength =		USB_DT_INTERFACE_SIZE,
	.bDescriptorType =	USB_DT_INTERFACE,
	.bInterfaceNumber =	0,
	.bAlternateSetting =	0,
	.bNumEndpoints =	1,
	.bInterfaceClass =	USB_CLASS_HID,
	.bInterfaceSubClass =	1,
	.bInterfaceProtocol =	1,
	.iInterface =		STRING_ID_INTERFACE,
};

struct usb_endpoint_descriptor usb_endpoint = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,
	.bEndpointAddress =	USB_DIR_IN | 1,
	.bmAttributes =		USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize =	8,
	.bInterval =		5,
};

char usb_hid_report[] = {
	0x05, 0x01,                    // Usage Page (Generic Desktop)        0
	0x09, 0x06,                    // Usage (Keyboard)                    2
	0xa1, 0x01,                    // Collection (Application)            4
	0x05, 0x07,                    //  Usage Page (Keyboard)              6
	0x19, 0xe0,                    //  Usage Minimum (224)                8
	0x29, 0xe7,                    //  Usage Maximum (231)                10
	0x15, 0x00,                    //  Logical Minimum (0)                12
	0x25, 0x01,                    //  Logical Maximum (1)                14
	0x75, 0x01,                    //  Report Size (1)                    16
	0x95, 0x08,                    //  Report Count (8)                   18
	0x81, 0x02,                    //  Input (Data,Var,Abs)               20
	0x95, 0x01,                    //  Report Count (1)                   22
	0x75, 0x08,                    //  Report Size (8)                    24
	0x81, 0x01,                    //  Input (Cnst,Arr,Abs)               26
	0x95, 0x03,                    //  Report Count (3)                   28
	0x75, 0x01,                    //  Report Size (1)                    30
	0x05, 0x08,                    //  Usage Page (LEDs)                  32
	0x19, 0x01,                    //  Usage Minimum (1)                  34
	0x29, 0x03,                    //  Usage Maximum (3)                  36
	0x91, 0x02,                    //  Output (Data,Var,Abs)              38
	0x95, 0x05,                    //  Report Count (5)                   40
	0x75, 0x01,                    //  Report Size (1)                    42
	0x91, 0x01,                    //  Output (Cnst,Arr,Abs)              44
	0x95, 0x06,                    //  Report Count (6)                   46
	0x75, 0x08,                    //  Report Size (8)                    48
	0x15, 0x00,                    //  Logical Minimum (0)                50
	0x26, 0xff, 0x00,              //  Logical Maximum (255)              52
	0x05, 0x07,                    //  Usage Page (Keyboard)              55
	0x19, 0x00,                    //  Usage Minimum (0)                  57
	0x2a, 0xff, 0x00,              //  Usage Maximum (255)                59
	0x81, 0x00,                    //  Input (Data,Arr,Abs)               62
	0xc0,                          // End Collection                      64
};

struct hid_descriptor usb_hid = {
	.bLength =		9,
	.bDescriptorType =	HID_DT_HID,
	.bcdHID =		__constant_cpu_to_le16(0x0110),
	.bCountryCode =		0,
	.bNumDescriptors =	1,
	.desc =			{
		{
			.bDescriptorType =	HID_DT_REPORT,
			.wDescriptorLength =	sizeof(usb_hid_report),
		}
	},
};

int build_config(char *data, int length) {
	struct usb_config_descriptor *config = (struct usb_config_descriptor *)data;
	int total_length = 0;

	assert(length >= sizeof(usb_config));
	memcpy(data, &usb_config, sizeof(usb_config));
	data += sizeof(usb_config);
	length -= sizeof(usb_config);
	total_length += sizeof(usb_config);

	assert(length >= sizeof(usb_interface));
	memcpy(data, &usb_interface, sizeof(usb_interface));
	data += sizeof(usb_interface);
	length -= sizeof(usb_interface);
	total_length += sizeof(usb_interface);

	assert(length >= sizeof(usb_hid));
	memcpy(data, &usb_hid, sizeof(usb_hid));
	data += sizeof(usb_hid);
	length -= sizeof(usb_hid);
	total_length += sizeof(usb_hid);

	assert(length >= USB_DT_ENDPOINT_SIZE);
	memcpy(data, &usb_endpoint, USB_DT_ENDPOINT_SIZE);
	data += USB_DT_ENDPOINT_SIZE;
	length -= USB_DT_ENDPOINT_SIZE;
	total_length += USB_DT_ENDPOINT_SIZE;

	config->wTotalLength = __cpu_to_le16(total_length);
	printf("config->wTotalLength: %d\n", total_length);

	return total_length;
}

/*----------------------------------------------------------------------*/

void log_control_request(struct usb_ctrlrequest *ctrl) {
	printf("  bRequestType: 0x%x (%s), bRequest: 0x%x, wValue: 0x%x, wIndex: 0x%x, wLength: %d\n",
		ctrl->bRequestType, (ctrl->bRequestType & USB_DIR_IN) ? "IN" : "OUT",
		ctrl->bRequest, ctrl->wValue, ctrl->wIndex, ctrl->wLength);

	switch (ctrl->bRequestType & USB_TYPE_MASK) {
	case USB_TYPE_STANDARD:
		printf("  type = USB_TYPE_STANDARD\n");
		break;
	case USB_TYPE_CLASS:
		printf("  type = USB_TYPE_CLASS\n");
		break;
	case USB_TYPE_VENDOR:
		printf("  type = USB_TYPE_VENDOR\n");
		break;
	default:
		printf("  type = unknown = %d\n", (int)ctrl->bRequestType);
		break;
	}

	switch (ctrl->bRequestType & USB_TYPE_MASK) {
	case USB_TYPE_STANDARD:
		switch (ctrl->bRequest) {
		case USB_REQ_GET_DESCRIPTOR:
			printf("  req = USB_REQ_GET_DESCRIPTOR\n");
			switch (ctrl->wValue >> 8) {
			case USB_DT_DEVICE:
				printf("  descriptor = USB_DT_DEVICE\n");
				break;
			case USB_DT_CONFIG:
				printf("  descriptor = USB_DT_CONFIG, index = %d\n", (int)(ctrl->wValue & 0xff));
				break;
			case USB_DT_STRING:
				printf("  descriptor = USB_DT_STRING\n");
				break;
			case USB_DT_INTERFACE:
				printf("  descriptor = USB_DT_INTERFACE\n");
				break;
			case USB_DT_ENDPOINT:
				printf("  descriptor = USB_DT_ENDPOINT\n");
				break;
			case USB_DT_DEVICE_QUALIFIER:
				printf("  descriptor = USB_DT_DEVICE_QUALIFIER\n");
				break;
			case USB_DT_OTHER_SPEED_CONFIG:
				printf("  descriptor = USB_DT_OTHER_SPEED_CONFIG\n");
				break;
			case USB_DT_INTERFACE_POWER:
				printf("  descriptor = USB_DT_INTERFACE_POWER\n");
				break;
			case USB_DT_OTG:
				printf("  descriptor = USB_DT_OTG\n");
				break;
			case USB_DT_DEBUG:
				printf("  descriptor = USB_DT_DEBUG\n");
				break;
			case USB_DT_INTERFACE_ASSOCIATION:
				printf("  descriptor = USB_DT_INTERFACE_ASSOCIATION\n");
				break;
			case USB_DT_SECURITY:
				printf("  descriptor = USB_DT_SECURITY\n");
				break;
			case USB_DT_KEY:
				printf("  descriptor = USB_DT_KEY\n");
				break;
			case USB_DT_ENCRYPTION_TYPE:
				printf("  descriptor = USB_DT_ENCRYPTION_TYPE\n");
				break;
			case USB_DT_BOS:
				printf("  descriptor = USB_DT_BOS\n");
				break;
			case USB_DT_DEVICE_CAPABILITY:
				printf("  descriptor = USB_DT_DEVICE_CAPABILITY\n");
				break;
			case USB_DT_WIRELESS_ENDPOINT_COMP:
				printf("  descriptor = USB_DT_WIRELESS_ENDPOINT_COMP\n");
				break;
			case USB_DT_PIPE_USAGE:
				printf("  descriptor = USB_DT_PIPE_USAGE\n");
				break;
			case USB_DT_SS_ENDPOINT_COMP:
				printf("  descriptor = USB_DT_SS_ENDPOINT_COMP\n");
				break;
			case HID_DT_HID:
				printf("  descriptor = HID_DT_HID\n");
				return;
			case HID_DT_REPORT:
				printf("  descriptor = HID_DT_REPORT\n");
				return;
			case HID_DT_PHYSICAL:
				printf("  descriptor = HID_DT_PHYSICAL\n");
				return;
			default:
				printf("  descriptor = unknown = 0x%x\n", (int)(ctrl->wValue >> 8));
				break;
			}
			break;
		case USB_REQ_SET_CONFIGURATION:
			printf("  req = USB_REQ_SET_CONFIGURATION, value = %d\n", (int)ctrl->wValue);
			break;
		case USB_REQ_GET_CONFIGURATION:
			printf("  req = USB_REQ_GET_CONFIGURATION\n");
			break;
		case USB_REQ_SET_INTERFACE:
			printf("  req = USB_REQ_SET_INTERFACE\n");
			break;
		case USB_REQ_GET_INTERFACE:
			printf("  req = USB_REQ_GET_INTERFACE\n");
			break;
		case USB_REQ_GET_STATUS:
			printf("  req = USB_REQ_GET_STATUS\n");
			break;
		case USB_REQ_CLEAR_FEATURE:
			printf("  req = USB_REQ_CLEAR_FEATURE\n");
			break;
		case USB_REQ_SET_FEATURE:
			printf("  req = USB_REQ_SET_FEATURE\n");
			break;
		default:
			printf("  req = unknown = 0x%x\n", (int)ctrl->bRequest);
			break;
		}
		break;
	case USB_TYPE_CLASS:
		switch (ctrl->bRequest) {
		case HID_REQ_GET_REPORT:
			printf("  req = HID_REQ_GET_REPORT\n");
			break;
		case HID_REQ_GET_IDLE:
			printf("  req = HID_REQ_GET_IDLE\n");
			break;
		case HID_REQ_GET_PROTOCOL:
			printf("  req = HID_REQ_GET_PROTOCOL\n");
			break;
		case HID_REQ_SET_REPORT:
			printf("  req = HID_REQ_SET_REPORT\n");
			break;
		case HID_REQ_SET_IDLE:
			printf("  req = HID_REQ_SET_IDLE\n");
			break;
		case HID_REQ_SET_PROTOCOL:
			printf("  req = HID_REQ_SET_PROTOCOL\n");
			break;
		default:
			printf("  req = unknown = 0x%x\n", (int)ctrl->bRequest);
			break;
		}
		break;
	default:
		printf("  req = unknown = 0x%x\n", (int)ctrl->bRequest);
		break;
	}
}

void log_event(struct usb_raw_event *event) {
	switch (event->type) {
	case USB_RAW_EVENT_CONNECT:
		printf("event: connect, length: %u\n", event->length);
		break;
	case USB_RAW_EVENT_CONTROL:
		printf("event: control, length: %u\n", event->length);
		log_control_request((struct usb_ctrlrequest *)&event->data[0]);
		break;
	default:
		printf("event: unknown, length: %u\n", event->length);
	}
}

/*----------------------------------------------------------------------*/

struct usb_raw_control_event {
	struct usb_raw_event		inner;
	struct usb_ctrlrequest		ctrl;
};

struct usb_raw_control_io {
	struct usb_raw_ep_io		inner;
	char				data[MAX_PACKET_SIZE];
};

struct usb_raw_keyboard_io {
	struct usb_raw_ep_io		inner;
	char				data[8];
};

int keyboard_connect(int fd) {
	int config_length;
	int ep = -1;

	bool done = false;
	while (!done) {
		struct usb_raw_control_event event;
		event.inner.type = 0;
		event.inner.length = sizeof(event.ctrl);

		struct usb_raw_control_io response;
		response.inner.ep = 0;
		response.inner.flags = 0;
		response.inner.length = 0;

		USB_RAW_EVENT_fetch(fd, (struct usb_raw_event *)&event);
		log_event((struct usb_raw_event *)&event);
		if (event.inner.type != USB_RAW_EVENT_CONTROL)
			continue;

		switch (event.ctrl.bRequestType & USB_TYPE_MASK) {
		case USB_TYPE_STANDARD:
			switch (event.ctrl.bRequest) {
			case USB_REQ_GET_DESCRIPTOR:
				switch (event.ctrl.wValue >> 8) {
				case USB_DT_DEVICE:
					memcpy(&response.data[0], &usb_device, sizeof(usb_device));
					response.inner.length = sizeof(usb_device);
					goto reply;
				case USB_DT_DEVICE_QUALIFIER:
					memcpy(&response.data[0], &usb_qualifier, sizeof(usb_qualifier));
					response.inner.length = sizeof(usb_qualifier);
					goto reply;
				case USB_DT_CONFIG:
					config_length = build_config(&response.data[0], sizeof(response.data));
					response.inner.length = config_length;
					goto reply;
				case USB_DT_STRING:
					response.data[0] = 4;
					response.data[1] = USB_DT_STRING;
					if ((event.ctrl.wValue & 0xff) == 0) {
						response.data[2] = 0x09;
						response.data[3] = 0x04;
					} else {
						response.data[2] = 'x';
						response.data[3] = 0x00;
					}
					response.inner.length = 4;
					goto reply;
				case HID_DT_REPORT:
					memcpy(&response.data[0], &usb_hid_report[0], sizeof(usb_hid_report));
					response.inner.length = sizeof(usb_hid_report);
					goto reply;
				default:
					printf("fail: no response\n");
					exit(EXIT_FAILURE);
				}
				break;
			case USB_REQ_SET_CONFIGURATION:
				ep = usb_raw_ep_enable(fd, &usb_endpoint);
				usb_raw_vbus_draw(fd, usb_config.bMaxPower);
				usb_raw_configure(fd);
				response.inner.length = 0;
				goto reply;
			case USB_REQ_GET_INTERFACE:
				response.data[0] = usb_interface.bInterfaceNumber;
				response.inner.length = 1;
				goto reply;
			default:
				printf("fail: no response\n");
				exit(EXIT_FAILURE);
			}
			break;
		case USB_TYPE_CLASS:
			switch (event.ctrl.bRequest) {
			case HID_REQ_SET_REPORT:
				response.inner.length = 1;
				done = true;
				goto reply;
			case HID_REQ_SET_IDLE:
				response.inner.length = 0;
				goto reply;
			case HID_REQ_SET_PROTOCOL:
				response.inner.length = 0;
				done = true;
				goto reply;
			default:
				printf("fail: no response\n");
				exit(EXIT_FAILURE);
			}
			break;
		default:
			printf("fail: no response\n");
			exit(EXIT_FAILURE);
		}

reply:
		if (event.ctrl.wLength < response.inner.length)
			response.inner.length = event.ctrl.wLength;
		if (event.ctrl.bRequestType & USB_DIR_IN)
			usb_raw_ep0_write(fd, (struct usb_raw_ep_io *)&response);
		else
			usb_raw_ep0_read(fd, (struct usb_raw_ep_io *)&response);
	}

	printf("endpoint: #%d\n", ep);
	return ep;
}

void keyboard_loop(int fd, int ep) {
	struct usb_raw_keyboard_io io;
	io.inner.ep = ep;
	io.inner.flags = 0;
	io.inner.length = 8;

	while (true) {
		memcpy(&io.inner.data[0], "\x00\x00\x1b\x00\x00\x00\x00\x00", 8);
		int rv = usb_raw_ep_write(fd, (struct usb_raw_ep_io *)&io);
		printf("key down: %d\n", rv);

		memcpy(&io.inner.data[0], "\x00\x00\x00\x00\x00\x00\x00\x00", 8);
		rv = usb_raw_ep_write(fd, (struct usb_raw_ep_io *)&io);
		printf("key up: %d\n", rv);

		sleep(1);
	}
}

int main(int argc, char **argv) {
	int fd = usb_raw_open();
	usb_raw_init(fd, USB_SPEED_HIGH);
	usb_raw_run(fd);

	int ep = keyboard_connect(fd);

	keyboard_loop(fd, ep);

	close(fd);

	return 0;
}
