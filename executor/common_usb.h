// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

// Implementation of syz_usb_* pseudo-syscalls.

#define USB_MAX_IFACE_NUM 4
#define USB_MAX_EP_NUM 32

struct usb_iface_index {
	struct usb_interface_descriptor* iface;
	uint8 bInterfaceNumber;
	uint8 bAlternateSetting;
	uint8 bInterfaceClass;
	struct usb_endpoint_descriptor eps[USB_MAX_EP_NUM];
	int eps_num;
};

struct usb_device_index {
	struct usb_device_descriptor* dev;
	struct usb_config_descriptor* config;
	uint8 bDeviceClass;
	uint8 bMaxPower;
	int config_length;
	struct usb_iface_index ifaces[USB_MAX_IFACE_NUM];
	int ifaces_num;
	int iface_cur;
};

static bool parse_usb_descriptor(char* buffer, size_t length, struct usb_device_index* index)
{
	if (length < sizeof(*index->dev) + sizeof(*index->config))
		return false;

	memset(index, 0, sizeof(*index));

	index->dev = (struct usb_device_descriptor*)buffer;
	index->config = (struct usb_config_descriptor*)(buffer + sizeof(*index->dev));
	index->bDeviceClass = index->dev->bDeviceClass;
	index->bMaxPower = index->config->bMaxPower;
	index->config_length = length - sizeof(*index->dev);
	index->iface_cur = -1;
	size_t offset = 0;

	while (true) {
		if (offset + 1 >= length)
			break;
		uint8 desc_length = buffer[offset];
		uint8 desc_type = buffer[offset + 1];
		if (desc_length <= 2)
			break;
		if (offset + desc_length > length)
			break;
		if (desc_type == USB_DT_INTERFACE && index->ifaces_num < USB_MAX_IFACE_NUM) {
			struct usb_interface_descriptor* iface = (struct usb_interface_descriptor*)(buffer + offset);
			debug("parse_usb_descriptor: found interface #%u (%d, %d) at %p\n",
			      index->ifaces_num, iface->bInterfaceNumber, iface->bAlternateSetting, iface);
			index->ifaces[index->ifaces_num].iface = iface;
			index->ifaces[index->ifaces_num].bInterfaceNumber = iface->bInterfaceNumber;
			index->ifaces[index->ifaces_num].bAlternateSetting = iface->bAlternateSetting;
			index->ifaces[index->ifaces_num].bInterfaceClass = iface->bInterfaceClass;
			index->ifaces_num++;
		}
		if (desc_type == USB_DT_ENDPOINT && index->ifaces_num > 0) {
			struct usb_iface_index* iface = &index->ifaces[index->ifaces_num - 1];
			debug("parse_usb_descriptor: found endpoint #%u at %p\n", iface->eps_num, buffer + offset);
			if (iface->eps_num < USB_MAX_EP_NUM) {
				memcpy(&iface->eps[iface->eps_num], buffer + offset, sizeof(iface->eps[iface->eps_num]));
				iface->eps_num++;
			}
		}
		offset += desc_length;
	}

	return true;
}

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
	__u32 type;
	__u32 length;
	__u8 data[0];
};

struct usb_raw_ep_io {
	__u16 ep;
	__u16 flags;
	__u32 length;
	__u8 data[0];
};

#define USB_RAW_IOCTL_INIT _IOW('U', 0, struct usb_raw_init)
#define USB_RAW_IOCTL_RUN _IO('U', 1)
#define USB_RAW_IOCTL_EVENT_FETCH _IOR('U', 2, struct usb_raw_event)
#define USB_RAW_IOCTL_EP0_WRITE _IOW('U', 3, struct usb_raw_ep_io)
#define USB_RAW_IOCTL_EP0_READ _IOWR('U', 4, struct usb_raw_ep_io)
#define USB_RAW_IOCTL_EP_ENABLE _IOW('U', 5, struct usb_endpoint_descriptor)
#define USB_RAW_IOCTL_EP_DISABLE _IOW('U', 6, __u32)
#define USB_RAW_IOCTL_EP_WRITE _IOW('U', 7, struct usb_raw_ep_io)
#define USB_RAW_IOCTL_EP_READ _IOWR('U', 8, struct usb_raw_ep_io)
#define USB_RAW_IOCTL_CONFIGURE _IO('U', 9)
#define USB_RAW_IOCTL_VBUS_DRAW _IOW('U', 10, __u32)

static int usb_raw_open()
{
	return open("/dev/raw-gadget", O_RDWR);
}

static int usb_raw_init(int fd, uint32 speed, const char* driver, const char* device)
{
	struct usb_raw_init arg;
	strncpy((char*)&arg.driver_name[0], driver, sizeof(arg.driver_name));
	strncpy((char*)&arg.device_name[0], device, sizeof(arg.device_name));
	arg.speed = speed;
	return ioctl(fd, USB_RAW_IOCTL_INIT, &arg);
}

static int usb_raw_run(int fd)
{
	return ioctl(fd, USB_RAW_IOCTL_RUN, 0);
}

static int usb_raw_event_fetch(int fd, struct usb_raw_event* event)
{
	return ioctl(fd, USB_RAW_IOCTL_EVENT_FETCH, event);
}

static int usb_raw_ep0_write(int fd, struct usb_raw_ep_io* io)
{
	return ioctl(fd, USB_RAW_IOCTL_EP0_WRITE, io);
}

static int usb_raw_ep0_read(int fd, struct usb_raw_ep_io* io)
{
	return ioctl(fd, USB_RAW_IOCTL_EP0_READ, io);
}

#if SYZ_EXECUTOR || __NR_syz_usb_ep_write
static int usb_raw_ep_write(int fd, struct usb_raw_ep_io* io)
{
	return ioctl(fd, USB_RAW_IOCTL_EP_WRITE, io);
}
#endif

#if SYZ_EXECUTOR || __NR_syz_usb_ep_read
static int usb_raw_ep_read(int fd, struct usb_raw_ep_io* io)
{
	return ioctl(fd, USB_RAW_IOCTL_EP_READ, io);
}
#endif

static int usb_raw_ep_enable(int fd, struct usb_endpoint_descriptor* desc)
{
	return ioctl(fd, USB_RAW_IOCTL_EP_ENABLE, desc);
}

static int usb_raw_ep_disable(int fd, int ep)
{
	return ioctl(fd, USB_RAW_IOCTL_EP_DISABLE, ep);
}

static int usb_raw_configure(int fd)
{
	return ioctl(fd, USB_RAW_IOCTL_CONFIGURE, 0);
}

static int usb_raw_vbus_draw(int fd, uint32 power)
{
	return ioctl(fd, USB_RAW_IOCTL_VBUS_DRAW, power);
}

#define MAX_USB_FDS 6

struct usb_info {
	int fd;
	struct usb_device_index index;
};

static struct usb_info usb_devices[MAX_USB_FDS];
static int usb_devices_num;

static struct usb_device_index* add_usb_index(int fd, char* dev, size_t dev_len)
{
	int i = __atomic_fetch_add(&usb_devices_num, 1, __ATOMIC_RELAXED);
	if (i >= MAX_USB_FDS)
		return NULL;

	int rv = 0;
	NONFAILING(rv = parse_usb_descriptor(dev, dev_len, &usb_devices[i].index));
	if (!rv)
		return NULL;

	__atomic_store_n(&usb_devices[i].fd, fd, __ATOMIC_RELEASE);
	return &usb_devices[i].index;
}

static struct usb_device_index* lookup_usb_index(int fd)
{
	int i;
	for (i = 0; i < MAX_USB_FDS; i++) {
		if (__atomic_load_n(&usb_devices[i].fd, __ATOMIC_ACQUIRE) == fd) {
			return &usb_devices[i].index;
		}
	}
	return NULL;
}

#if SYZ_EXECUTOR || __NR_syz_usb_control_io
static int lookup_interface(int fd, uint8 bInterfaceNumber, uint8 bAlternateSetting)
{
	struct usb_device_index* index = lookup_usb_index(fd);
	int i;

	if (!index)
		return -1;

	for (i = 0; i < index->ifaces_num; i++) {
		if (index->ifaces[i].bInterfaceNumber == bInterfaceNumber &&
		    index->ifaces[i].bAlternateSetting == bAlternateSetting)
			return i;
	}
	return -1;
}
#endif

static void set_interface(int fd, int n)
{
	struct usb_device_index* index = lookup_usb_index(fd);
	int ep;

	if (!index)
		return;

	if (index->iface_cur >= 0 && index->iface_cur < index->ifaces_num) {
		for (ep = 0; ep < index->ifaces[index->iface_cur].eps_num; ep++) {
			int rv = usb_raw_ep_disable(fd, ep);
			if (rv < 0) {
				debug("set_interface: failed to disable endpoint %d\n", ep);
			} else {
				debug("set_interface: endpoint %d disabled\n", ep);
			}
		}
	}
	if (n >= 0 && n < index->ifaces_num) {
		for (ep = 0; ep < index->ifaces[n].eps_num; ep++) {
			int rv = usb_raw_ep_enable(fd, &index->ifaces[n].eps[ep]);
			if (rv < 0) {
				debug("set_interface: failed to enable endpoint %d\n", ep);
			} else {
				debug("set_interface: endpoint %d enabled as %d\n", ep, rv);
			}
		}
		index->iface_cur = n;
	}
}

static int configure_device(int fd)
{
	struct usb_device_index* index = lookup_usb_index(fd);

	if (!index)
		return -1;

	int rv = usb_raw_vbus_draw(fd, index->bMaxPower);
	if (rv < 0) {
		debug("configure_device: usb_raw_vbus_draw failed with %d\n", rv);
		return rv;
	}
	rv = usb_raw_configure(fd);
	if (rv < 0) {
		debug("configure_device: usb_raw_configure failed with %d\n", rv);
		return rv;
	}
	set_interface(fd, 0);
	return 0;
}

#if USB_DEBUG

#include <linux/hid.h>
#include <linux/usb/audio.h>
#include <linux/usb/cdc.h>
#include <linux/usb/ch11.h>
#include <linux/usb/ch9.h>

// drivers/usb/class/usblp.c
#define USBLP_REQ_GET_ID 0x00
#define USBLP_REQ_GET_STATUS 0x01
#define USBLP_REQ_RESET 0x02

const char* usb_class_to_string(unsigned value)
{
	switch (value) {
	case USB_CLASS_PER_INTERFACE:
		return "USB_CLASS_PER_INTERFACE";
	case USB_CLASS_AUDIO:
		return "USB_CLASS_AUDIO";
	case USB_CLASS_COMM:
		return "USB_CLASS_COMM";
	case USB_CLASS_HID:
		return "USB_CLASS_HID";
	case USB_CLASS_PHYSICAL:
		return "USB_CLASS_PHYSICAL";
	case USB_CLASS_STILL_IMAGE:
		return "USB_CLASS_STILL_IMAGE";
	case USB_CLASS_PRINTER:
		return "USB_CLASS_PRINTER";
	case USB_CLASS_MASS_STORAGE:
		return "USB_CLASS_MASS_STORAGE";
	case USB_CLASS_HUB:
		return "USB_CLASS_HUB";
	case USB_CLASS_CDC_DATA:
		return "USB_CLASS_CDC_DATA";
	case USB_CLASS_CSCID:
		return "USB_CLASS_CSCID";
	case USB_CLASS_CONTENT_SEC:
		return "USB_CLASS_CONTENT_SEC";
	case USB_CLASS_VIDEO:
		return "USB_CLASS_VIDEO";
	case USB_CLASS_WIRELESS_CONTROLLER:
		return "USB_CLASS_WIRELESS_CONTROLLER";
	case USB_CLASS_MISC:
		return "USB_CLASS_MISC";
	case USB_CLASS_APP_SPEC:
		return "USB_CLASS_APP_SPEC";
	case USB_CLASS_VENDOR_SPEC:
		return "USB_CLASS_VENDOR_SPEC";
	}
	return "unknown";
}

static void analyze_usb_device(struct usb_device_index* index)
{
	debug("analyze_usb_device: idVendor = %04x\n", (unsigned)index->dev->idVendor);
	debug("analyze_usb_device: idProduct = %04x\n", (unsigned)index->dev->idProduct);

	debug("analyze_usb_device: bDeviceClass = %x (%s)\n", (unsigned)index->dev->bDeviceClass,
	      usb_class_to_string(index->dev->bDeviceClass));
	debug("analyze_usb_device: bDeviceSubClass = %x\n", (unsigned)index->dev->bDeviceSubClass);
	debug("analyze_usb_device: bDeviceProtocol = %x\n", (unsigned)index->dev->bDeviceProtocol);

	for (int i = 0; i < index->ifaces_num; i++) {
		struct usb_interface_descriptor* iface = index->ifaces[i].iface;
		debug("analyze_usb_device: interface #%d:\n", i);
		debug("analyze_usb_device: bInterfaceClass = %x (%s)\n", (unsigned)iface->bInterfaceClass,
		      usb_class_to_string(iface->bInterfaceClass));
		debug("analyze_usb_device: bInterfaceSubClass = %x\n", (unsigned)iface->bInterfaceSubClass);
		debug("analyze_usb_device: bInterfaceProtocol = %x\n", (unsigned)iface->bInterfaceProtocol);
	}
}

static bool analyze_control_request_standard(struct usb_device_index* index, struct usb_ctrlrequest* ctrl)
{
	uint8 bDeviceClass = index->bDeviceClass;
	uint8 bInterfaceClass = index->ifaces[index->iface_cur].bInterfaceClass;

	// For some reason HID class GET_DESCRIPTOR requests are STANDARD.
	if (bDeviceClass == USB_CLASS_HID || bInterfaceClass == USB_CLASS_HID) {
		switch (ctrl->bRequest) {
		case USB_REQ_GET_DESCRIPTOR:
			debug("analyze_control_request: req = USB_REQ_GET_DESCRIPTOR\n");
			switch (ctrl->wValue >> 8) {
			case HID_DT_HID:
				debug("analyze_control_request: desc = HID_DT_HID\n");
				return true;
			case HID_DT_REPORT:
				debug("analyze_control_request: desc = HID_DT_REPORT\n");
				return true;
			case HID_DT_PHYSICAL:
				debug("analyze_control_request: desc = HID_DT_PHYSICAL\n");
				return false;
			}
		}
		// Fallthrough to lookup normal STANDARD requests.
	}

	switch (ctrl->bRequest) {
	case USB_REQ_GET_DESCRIPTOR:
		debug("analyze_control_request: req = USB_REQ_GET_DESCRIPTOR\n");
		switch (ctrl->wValue >> 8) {
		case USB_DT_DEVICE:
			debug("analyze_control_request: desc = USB_DT_DEVICE\n");
			return true;
		case USB_DT_CONFIG:
			debug("analyze_control_request: desc = USB_DT_CONFIG, index = %d\n", (int)(ctrl->wValue & 0xff));
			return true;
		case USB_DT_STRING:
			debug("analyze_control_request: desc = USB_DT_STRING\n");
			return true;
		case USB_DT_INTERFACE:
			debug("analyze_control_request: desc = USB_DT_INTERFACE\n");
			break;
		case USB_DT_ENDPOINT:
			debug("analyze_control_request: desc = USB_DT_ENDPOINT\n");
			break;
		case USB_DT_DEVICE_QUALIFIER:
			debug("analyze_control_request: desc = USB_DT_DEVICE_QUALIFIER\n");
			return true;
		case USB_DT_OTHER_SPEED_CONFIG:
			debug("analyze_control_request: desc = USB_DT_OTHER_SPEED_CONFIG\n");
			break;
		case USB_DT_INTERFACE_POWER:
			debug("analyze_control_request: desc = USB_DT_INTERFACE_POWER\n");
			break;
		case USB_DT_OTG:
			debug("analyze_control_request: desc = USB_DT_OTG\n");
			break;
		case USB_DT_DEBUG:
			debug("analyze_control_request: desc = USB_DT_DEBUG\n");
			break;
		case USB_DT_INTERFACE_ASSOCIATION:
			debug("analyze_control_request: desc = USB_DT_INTERFACE_ASSOCIATION\n");
			break;
		case USB_DT_SECURITY:
			debug("analyze_control_request: desc = USB_DT_SECURITY\n");
			break;
		case USB_DT_KEY:
			debug("analyze_control_request: desc = USB_DT_KEY\n");
			break;
		case USB_DT_ENCRYPTION_TYPE:
			debug("analyze_control_request: desc = USB_DT_ENCRYPTION_TYPE\n");
			break;
		case USB_DT_BOS:
			debug("analyze_control_request: desc = USB_DT_BOS\n");
			return true;
		case USB_DT_DEVICE_CAPABILITY:
			debug("analyze_control_request: desc = USB_DT_DEVICE_CAPABILITY\n");
			break;
		case USB_DT_WIRELESS_ENDPOINT_COMP:
			debug("analyze_control_request: desc = USB_DT_WIRELESS_ENDPOINT_COMP\n");
			break;
		case USB_DT_WIRE_ADAPTER:
			debug("analyze_control_request: desc = USB_DT_WIRE_ADAPTER\n");
			break;
		case USB_DT_RPIPE:
			debug("analyze_control_request: desc = USB_DT_RPIPE\n");
			break;
		case USB_DT_CS_RADIO_CONTROL:
			debug("analyze_control_request: desc = USB_DT_CS_RADIO_CONTROL\n");
			break;
		case USB_DT_PIPE_USAGE:
			debug("analyze_control_request: desc = USB_DT_PIPE_USAGE\n");
			break;
		case USB_DT_SS_ENDPOINT_COMP:
			debug("analyze_control_request: desc = USB_DT_SS_ENDPOINT_COMP\n");
			break;
		case USB_DT_SSP_ISOC_ENDPOINT_COMP:
			debug("analyze_control_request: desc = USB_DT_SSP_ISOC_ENDPOINT_COMP\n");
			break;
		default:
			debug("analyze_control_request: desc = unknown = 0x%x\n", (int)(ctrl->wValue >> 8));
			break;
		}
		break;
	case USB_REQ_GET_STATUS:
		debug("analyze_control_request: req = USB_REQ_GET_STATUS\n");
		break;
	case USB_REQ_CLEAR_FEATURE:
		debug("analyze_control_request: req = USB_REQ_CLEAR_FEATURE\n");
		break;
	case USB_REQ_SET_FEATURE:
		debug("analyze_control_request: req = USB_REQ_SET_FEATURE\n");
		break;
	case USB_REQ_GET_CONFIGURATION:
		debug("analyze_control_request: req = USB_REQ_GET_CONFIGURATION\n");
		return true;
	case USB_REQ_SET_CONFIGURATION:
		debug("analyze_control_request: req = USB_REQ_SET_CONFIGURATION\n");
		break;
	case USB_REQ_GET_INTERFACE:
		debug("analyze_control_request: req = USB_REQ_GET_INTERFACE\n");
		return true;
	case USB_REQ_SET_INTERFACE:
		debug("analyze_control_request: req = USB_REQ_SET_INTERFACE\n");
		break;
	default:
		debug("analyze_control_request: req = unknown = 0x%x\n", (int)ctrl->bRequest);
		break;
	}

	return false;
}

static bool analyze_control_request_class(struct usb_device_index* index, struct usb_ctrlrequest* ctrl)
{
	uint8 bDeviceClass = index->bDeviceClass;
	uint8 bInterfaceClass = index->ifaces[index->iface_cur].bInterfaceClass;

	if (bDeviceClass == USB_CLASS_HID || bInterfaceClass == USB_CLASS_HID) {
		switch (ctrl->bRequest) {
		case HID_REQ_GET_REPORT:
			debug("analyze_control_request: req = HID_REQ_GET_REPORT\n");
			return true;
		case HID_REQ_GET_IDLE:
			debug("analyze_control_request: req = HID_REQ_GET_IDLE\n");
			break;
		case HID_REQ_GET_PROTOCOL:
			debug("analyze_control_request: req = HID_REQ_GET_PROTOCOL\n");
			return true;
		case HID_REQ_SET_REPORT:
			debug("analyze_control_request: req = HID_REQ_SET_REPORT\n");
			break;
		case HID_REQ_SET_IDLE:
			debug("analyze_control_request: req = HID_REQ_SET_IDLE\n");
			break;
		case HID_REQ_SET_PROTOCOL:
			debug("analyze_control_request: req = HID_REQ_SET_PROTOCOL\n");
			break;
		}
	}

	if (bDeviceClass == USB_CLASS_AUDIO || bInterfaceClass == USB_CLASS_AUDIO) {
		switch (ctrl->bRequest) {
		case UAC_SET_CUR:
			debug("analyze_control_request: req = UAC_SET_CUR\n");
			break;
		case UAC_GET_CUR:
			debug("analyze_control_request: req = UAC_GET_CUR\n");
			return true;
		case UAC_SET_MIN:
			debug("analyze_control_request: req = UAC_SET_MIN\n");
			break;
		case UAC_GET_MIN:
			debug("analyze_control_request: req = UAC_GET_MIN\n");
			return true;
		case UAC_SET_MAX:
			debug("analyze_control_request: req = UAC_SET_MAX\n");
			break;
		case UAC_GET_MAX:
			debug("analyze_control_request: req = UAC_GET_MAX\n");
			return true;
		case UAC_SET_RES:
			debug("analyze_control_request: req = UAC_SET_RES\n");
			break;
		case UAC_GET_RES:
			debug("analyze_control_request: req = UAC_GET_RES\n");
			return true;
		case UAC_SET_MEM:
			debug("analyze_control_request: req = UAC_SET_MEM\n");
			break;
		case UAC_GET_MEM:
			debug("analyze_control_request: req = UAC_GET_MEM\n");
			return true;
		}
	}

	if (bDeviceClass == USB_CLASS_PRINTER || bInterfaceClass == USB_CLASS_PRINTER) {
		switch (ctrl->bRequest) {
		case USBLP_REQ_GET_ID:
			debug("analyze_control_request: req = USBLP_REQ_GET_ID\n");
			return true;
		case USBLP_REQ_GET_STATUS:
			debug("analyze_control_request: req = USBLP_REQ_GET_STATUS\n");
			return true;
		case USBLP_REQ_RESET:
			debug("analyze_control_request: req = USBLP_REQ_RESET\n");
			break;
		}
	}

	if (bDeviceClass == USB_CLASS_HUB || bInterfaceClass == USB_CLASS_HUB) {
		switch (ctrl->bRequest) {
		case USB_REQ_GET_DESCRIPTOR:
			switch (ctrl->wValue >> 8) {
			case USB_DT_HUB:
				debug("analyze_control_request: desc = USB_DT_HUB\n");
				return true;
			case USB_DT_SS_HUB:
				debug("analyze_control_request: desc = USB_DT_SS_HUB\n");
				return true;
			}
		case USB_REQ_GET_STATUS:
			debug("analyze_control_request: req = USB_REQ_GET_STATUS\n");
			return true;
		case HUB_SET_DEPTH:
			debug("analyze_control_request: req = HUB_SET_DEPTH\n");
			break;
		}
	}

	if (bInterfaceClass == USB_CLASS_COMM) {
		switch (ctrl->bRequest) {
		case USB_CDC_SEND_ENCAPSULATED_COMMAND:
			debug("analyze_control_request: req = USB_CDC_SEND_ENCAPSULATED_COMMAND\n");
			break;
		case USB_CDC_GET_ENCAPSULATED_RESPONSE:
			debug("analyze_control_request: req = USB_CDC_GET_ENCAPSULATED_RESPONSE\n");
			break;
		case USB_CDC_REQ_SET_LINE_CODING:
			debug("analyze_control_request: req = USB_CDC_REQ_SET_LINE_CODING\n");
			break;
		case USB_CDC_REQ_GET_LINE_CODING:
			debug("analyze_control_request: req = USB_CDC_REQ_GET_LINE_CODING\n");
			break;
		case USB_CDC_REQ_SET_CONTROL_LINE_STATE:
			debug("analyze_control_request: req = USB_CDC_REQ_SET_CONTROL_LINE_STATE\n");
			break;
		case USB_CDC_REQ_SEND_BREAK:
			debug("analyze_control_request: req = USB_CDC_REQ_SEND_BREAK\n");
			break;
		case USB_CDC_SET_ETHERNET_MULTICAST_FILTERS:
			debug("analyze_control_request: req = USB_CDC_SET_ETHERNET_MULTICAST_FILTERS\n");
			break;
		case USB_CDC_SET_ETHERNET_PM_PATTERN_FILTER:
			debug("analyze_control_request: req = USB_CDC_SET_ETHERNET_PM_PATTERN_FILTER\n");
			break;
		case USB_CDC_GET_ETHERNET_PM_PATTERN_FILTER:
			debug("analyze_control_request: req = USB_CDC_GET_ETHERNET_PM_PATTERN_FILTER\n");
			break;
		case USB_CDC_SET_ETHERNET_PACKET_FILTER:
			debug("analyze_control_request: req = USB_CDC_SET_ETHERNET_PACKET_FILTER\n");
			break;
		case USB_CDC_GET_ETHERNET_STATISTIC:
			debug("analyze_control_request: req = USB_CDC_GET_ETHERNET_STATISTIC\n");
			break;
		case USB_CDC_GET_NTB_PARAMETERS:
			debug("analyze_control_request: req = USB_CDC_GET_NTB_PARAMETERS\n");
			return true;
		case USB_CDC_GET_NET_ADDRESS:
			debug("analyze_control_request: req = USB_CDC_GET_NET_ADDRESS\n");
			break;
		case USB_CDC_SET_NET_ADDRESS:
			debug("analyze_control_request: req = USB_CDC_SET_NET_ADDRESS\n");
			break;
		case USB_CDC_GET_NTB_FORMAT:
			debug("analyze_control_request: req = USB_CDC_GET_NTB_FORMAT\n");
			return true;
		case USB_CDC_SET_NTB_FORMAT:
			debug("analyze_control_request: req = USB_CDC_SET_NTB_FORMAT\n");
			break;
		case USB_CDC_GET_NTB_INPUT_SIZE:
			debug("analyze_control_request: req = USB_CDC_GET_NTB_INPUT_SIZE\n");
			return true;
		case USB_CDC_SET_NTB_INPUT_SIZE:
			debug("analyze_control_request: req = USB_CDC_SET_NTB_INPUT_SIZE\n");
			break;
		case USB_CDC_GET_MAX_DATAGRAM_SIZE:
			debug("analyze_control_request: req = USB_CDC_GET_MAX_DATAGRAM_SIZE\n");
			return true;
		case USB_CDC_SET_MAX_DATAGRAM_SIZE:
			debug("analyze_control_request: req = USB_CDC_SET_MAX_DATAGRAM_SIZE\n");
			break;
		case USB_CDC_GET_CRC_MODE:
			debug("analyze_control_request: req = USB_CDC_GET_CRC_MODE\n");
			return true;
		case USB_CDC_SET_CRC_MODE:
			debug("analyze_control_request: req = USB_CDC_SET_CRC_MODE\n");
			break;
		}
	}

	return false;
}

static bool analyze_control_request_vendor(struct usb_device_index* index, struct usb_ctrlrequest* ctrl)
{
	// Ignore vendor requests for now.
	return true;
}

static void analyze_control_request(int fd, struct usb_ctrlrequest* ctrl)
{
	struct usb_device_index* index = lookup_usb_index(fd);

	if (!index)
		return;

	switch (ctrl->bRequestType & USB_TYPE_MASK) {
	case USB_TYPE_STANDARD:
		debug("analyze_control_request: type = USB_TYPE_STANDARD\n");
		if (analyze_control_request_standard(index, ctrl))
			return;
		break;
	case USB_TYPE_CLASS:
		debug("analyze_control_request: type = USB_TYPE_CLASS\n");
		if (analyze_control_request_class(index, ctrl))
			return;
		break;
	case USB_TYPE_VENDOR:
		debug("analyze_control_request: type = USB_TYPE_VENDOR\n");
		if (analyze_control_request_vendor(index, ctrl))
			return;
		break;
	}

	if (ctrl->bRequestType & USB_DIR_IN) {
		char message[128];
		debug("analyze_control_request: unknown control request\n");
		snprintf(&message[0], sizeof(message), "BUG: unknown control request (0x%x, 0x%x, 0x%x, 0x%x, %d)",
			 ctrl->bRequestType, ctrl->bRequest, ctrl->wValue, ctrl->wIndex, ctrl->wLength);
		write_file("/dev/kmsg", &message[0]);
	}
}

#endif // USB_DEBUG

#define USB_MAX_PACKET_SIZE 1024

struct usb_raw_control_event {
	struct usb_raw_event inner;
	struct usb_ctrlrequest ctrl;
	char data[USB_MAX_PACKET_SIZE];
};

struct usb_raw_ep_io_data {
	struct usb_raw_ep_io inner;
	char data[USB_MAX_PACKET_SIZE];
};

struct vusb_connect_string_descriptor {
	uint32 len;
	char* str;
} __attribute__((packed));

struct vusb_connect_descriptors {
	uint32 qual_len;
	char* qual;
	uint32 bos_len;
	char* bos;
	uint32 strs_len;
	struct vusb_connect_string_descriptor strs[0];
} __attribute__((packed));

static const char default_string[] = {
    8, USB_DT_STRING,
    's', 0, 'y', 0, 'z', 0 // UTF16-encoded "syz"
};

static const char default_lang_id[] = {
    4, USB_DT_STRING,
    0x09, 0x04 // English (United States)
};

static bool lookup_connect_response(int fd, struct vusb_connect_descriptors* descs, struct usb_ctrlrequest* ctrl,
				    char** response_data, uint32* response_length)
{
	struct usb_device_index* index = lookup_usb_index(fd);
	uint8 str_idx;

	if (!index)
		return false;

	switch (ctrl->bRequestType & USB_TYPE_MASK) {
	case USB_TYPE_STANDARD:
		switch (ctrl->bRequest) {
		case USB_REQ_GET_DESCRIPTOR:
			switch (ctrl->wValue >> 8) {
			case USB_DT_DEVICE:
				*response_data = (char*)index->dev;
				*response_length = sizeof(*index->dev);
				return true;
			case USB_DT_CONFIG:
				*response_data = (char*)index->config;
				*response_length = index->config_length;
				return true;
			case USB_DT_STRING:
				str_idx = (uint8)ctrl->wValue;
				if (descs && str_idx < descs->strs_len) {
					*response_data = descs->strs[str_idx].str;
					*response_length = descs->strs[str_idx].len;
					return true;
				}
				if (str_idx == 0) {
					*response_data = (char*)&default_lang_id[0];
					*response_length = default_lang_id[0];
					return true;
				}
				*response_data = (char*)&default_string[0];
				*response_length = default_string[0];
				return true;
			case USB_DT_BOS:
				*response_data = descs->bos;
				*response_length = descs->bos_len;
				return true;
			case USB_DT_DEVICE_QUALIFIER:
				if (!descs->qual) {
					// Fill in DEVICE_QUALIFIER based on DEVICE if not provided.
					struct usb_qualifier_descriptor* qual =
					    (struct usb_qualifier_descriptor*)response_data;
					qual->bLength = sizeof(*qual);
					qual->bDescriptorType = USB_DT_DEVICE_QUALIFIER;
					qual->bcdUSB = index->dev->bcdUSB;
					qual->bDeviceClass = index->dev->bDeviceClass;
					qual->bDeviceSubClass = index->dev->bDeviceSubClass;
					qual->bDeviceProtocol = index->dev->bDeviceProtocol;
					qual->bMaxPacketSize0 = index->dev->bMaxPacketSize0;
					qual->bNumConfigurations = index->dev->bNumConfigurations;
					qual->bRESERVED = 0;
					*response_length = sizeof(*qual);
					return true;
				}
				*response_data = descs->qual;
				*response_length = descs->qual_len;
				return true;
			default:
				fail("lookup_connect_response: no response");
				return false;
			}
			break;
		default:
			fail("lookup_connect_response: no response");
			return false;
		}
		break;
	default:
		fail("lookup_connect_response: no response");
		return false;
	}

	return false;
}

static volatile long syz_usb_connect(volatile long a0, volatile long a1, volatile long a2, volatile long a3)
{
	uint64 speed = a0;
	uint64 dev_len = a1;
	char* dev = (char*)a2;
	struct vusb_connect_descriptors* descs = (struct vusb_connect_descriptors*)a3;

	debug("syz_usb_connect: dev: %p\n", dev);
	if (!dev) {
		debug("syz_usb_connect: dev is null\n");
		return -1;
	}

	debug("syz_usb_connect: device data:\n");
	debug_dump_data(dev, dev_len);

	int fd = usb_raw_open();
	if (fd < 0) {
		debug("syz_usb_connect: usb_raw_open failed with %d\n", fd);
		return fd;
	}
	if (fd >= MAX_FDS) {
		close(fd);
		debug("syz_usb_connect: too many open fds\n");
		return -1;
	}
	debug("syz_usb_connect: usb_raw_open success\n");

	struct usb_device_index* index = add_usb_index(fd, dev, dev_len);
	if (!index) {
		debug("syz_usb_connect: add_usb_index failed\n");
		return -1;
	}
	debug("syz_usb_connect: add_usb_index success\n");

#if USB_DEBUG
	NONFAILING(analyze_usb_device(index));
#endif

	// TODO: consider creating two dummy_udc's per proc to increace the chance of
	// triggering interaction between multiple USB devices within the same program.
	char device[32];
	sprintf(&device[0], "dummy_udc.%llu", procid);
	int rv = usb_raw_init(fd, speed, "dummy_udc", &device[0]);
	if (rv < 0) {
		debug("syz_usb_connect: usb_raw_init failed with %d\n", rv);
		return rv;
	}
	debug("syz_usb_connect: usb_raw_init success\n");

	rv = usb_raw_run(fd);
	if (rv < 0) {
		debug("syz_usb_connect: usb_raw_run failed with %d\n", rv);
		return rv;
	}
	debug("syz_usb_connect: usb_raw_run success\n");

	bool done = false;
	while (!done) {
		struct usb_raw_control_event event;
		event.inner.type = 0;
		event.inner.length = sizeof(event.ctrl);
		rv = usb_raw_event_fetch(fd, (struct usb_raw_event*)&event);
		if (rv < 0) {
			debug("syz_usb_connect: usb_raw_event_fetch failed with %d\n", rv);
			return rv;
		}
		if (event.inner.type != USB_RAW_EVENT_CONTROL)
			continue;

		debug("syz_usb_connect: bReqType: 0x%x (%s), bReq: 0x%x, wVal: 0x%x, wIdx: 0x%x, wLen: %d\n",
		      event.ctrl.bRequestType, (event.ctrl.bRequestType & USB_DIR_IN) ? "IN" : "OUT",
		      event.ctrl.bRequest, event.ctrl.wValue, event.ctrl.wIndex, event.ctrl.wLength);

#if USB_DEBUG
		analyze_control_request(fd, &event.ctrl);
#endif

		bool response_found = false;
		char* response_data = NULL;
		uint32 response_length = 0;

		if (event.ctrl.bRequestType & USB_DIR_IN) {
			NONFAILING(response_found = lookup_connect_response(fd, descs, &event.ctrl, &response_data, &response_length));
			if (!response_found) {
				debug("syz_usb_connect: unknown control IN request\n");
				return -1;
			}
		} else {
			if ((event.ctrl.bRequestType & USB_TYPE_MASK) != USB_TYPE_STANDARD ||
			    event.ctrl.bRequest != USB_REQ_SET_CONFIGURATION) {
				fail("syz_usb_connect: unknown control OUT request");
				return -1;
			}
			done = true;
		}

		if (done) {
			rv = configure_device(fd);
			if (rv < 0) {
				debug("syz_usb_connect: configure_device failed with %d\n", rv);
				return rv;
			}
		}

		struct usb_raw_ep_io_data response;
		response.inner.ep = 0;
		response.inner.flags = 0;
		if (response_length > sizeof(response.data))
			response_length = 0;
		if (event.ctrl.wLength < response_length)
			response_length = event.ctrl.wLength;
		response.inner.length = response_length;
		if (response_data)
			memcpy(&response.data[0], response_data, response_length);
		else
			memset(&response.data[0], 0, response_length);

		if (event.ctrl.bRequestType & USB_DIR_IN) {
			debug("syz_usb_connect: writing %d bytes\n", response.inner.length);
			rv = usb_raw_ep0_write(fd, (struct usb_raw_ep_io*)&response);
		} else {
			rv = usb_raw_ep0_read(fd, (struct usb_raw_ep_io*)&response);
			debug("syz_usb_connect: read %d bytes\n", response.inner.length);
			debug_dump_data(&event.data[0], response.inner.length);
		}
		if (rv < 0) {
			debug("syz_usb_connect: usb_raw_ep0_read/write failed with %d\n", rv);
			return rv;
		}
	}

	sleep_ms(200);

	debug("syz_usb_connect: configured\n");

	return fd;
}

#if SYZ_EXECUTOR || __NR_syz_usb_control_io
struct vusb_descriptor {
	uint8 req_type;
	uint8 desc_type;
	uint32 len;
	char data[0];
} __attribute__((packed));

struct vusb_descriptors {
	uint32 len;
	struct vusb_descriptor* generic;
	struct vusb_descriptor* descs[0];
} __attribute__((packed));

struct vusb_response {
	uint8 type;
	uint8 req;
	uint32 len;
	char data[0];
} __attribute__((packed));

struct vusb_responses {
	uint32 len;
	struct vusb_response* generic;
	struct vusb_response* resps[0];
} __attribute__((packed));

static bool lookup_control_response(struct vusb_descriptors* descs, struct vusb_responses* resps,
				    struct usb_ctrlrequest* ctrl, char** response_data, uint32* response_length)
{
	int descs_num = 0;
	int resps_num = 0;

	if (descs)
		descs_num = (descs->len - offsetof(struct vusb_descriptors, descs)) / sizeof(descs->descs[0]);
	if (resps)
		resps_num = (resps->len - offsetof(struct vusb_responses, resps)) / sizeof(resps->resps[0]);

	uint8 req = ctrl->bRequest;
	uint8 req_type = ctrl->bRequestType & USB_TYPE_MASK;
	uint8 desc_type = ctrl->wValue >> 8;

	if (req == USB_REQ_GET_DESCRIPTOR) {
		int i;

		for (i = 0; i < descs_num; i++) {
			struct vusb_descriptor* desc = descs->descs[i];
			if (!desc)
				continue;
			if (desc->req_type == req_type && desc->desc_type == desc_type) {
				*response_length = desc->len;
				if (*response_length != 0)
					*response_data = &desc->data[0];
				else
					*response_data = NULL;
				return true;
			}
		}

		if (descs && descs->generic) {
			*response_data = &descs->generic->data[0];
			*response_length = descs->generic->len;
			return true;
		}
	} else {
		int i;

		for (i = 0; i < resps_num; i++) {
			struct vusb_response* resp = resps->resps[i];
			if (!resp)
				continue;
			if (resp->type == req_type && resp->req == req) {
				*response_length = resp->len;
				if (*response_length != 0)
					*response_data = &resp->data[0];
				else
					*response_data = NULL;
				return true;
			}
		}

		if (resps && resps->generic) {
			*response_data = &resps->generic->data[0];
			*response_length = resps->generic->len;
			return true;
		}
	}

	return false;
}

static volatile long syz_usb_control_io(volatile long a0, volatile long a1, volatile long a2)
{
	int fd = a0;
	struct vusb_descriptors* descs = (struct vusb_descriptors*)a1;
	struct vusb_responses* resps = (struct vusb_responses*)a2;

	struct usb_raw_control_event event;
	event.inner.type = 0;
	event.inner.length = USB_MAX_PACKET_SIZE;
	int rv = usb_raw_event_fetch(fd, (struct usb_raw_event*)&event);
	if (rv < 0) {
		debug("syz_usb_control_io: usb_raw_ep0_read failed with %d\n", rv);
		return rv;
	}
	if (event.inner.type != USB_RAW_EVENT_CONTROL) {
		debug("syz_usb_control_io: wrong event type: %d\n", (int)event.inner.type);
		return -1;
	}

	debug("syz_usb_control_io: bReqType: 0x%x (%s), bReq: 0x%x, wVal: 0x%x, wIdx: 0x%x, wLen: %d\n",
	      event.ctrl.bRequestType, (event.ctrl.bRequestType & USB_DIR_IN) ? "IN" : "OUT",
	      event.ctrl.bRequest, event.ctrl.wValue, event.ctrl.wIndex, event.ctrl.wLength);

#if USB_DEBUG
	analyze_control_request(fd, &event.ctrl);
#endif

	bool response_found = false;
	char* response_data = NULL;
	uint32 response_length = 0;

	if ((event.ctrl.bRequestType & USB_DIR_IN) && event.ctrl.wLength) {
		NONFAILING(response_found = lookup_control_response(descs, resps, &event.ctrl, &response_data, &response_length));
		if (!response_found) {
			debug("syz_usb_control_io: unknown control IN request\n");
			return -1;
		}
	} else {
		if ((event.ctrl.bRequestType & USB_TYPE_MASK) == USB_TYPE_STANDARD ||
		    event.ctrl.bRequest == USB_REQ_SET_INTERFACE) {
			int iface_num = event.ctrl.wIndex;
			int alt_set = event.ctrl.wValue;
			debug("syz_usb_control_io: setting interface (%d, %d)\n", iface_num, alt_set);
			int iface_index = lookup_interface(fd, iface_num, alt_set);
			if (iface_index < 0) {
				debug("syz_usb_control_io: interface (%d, %d) not found\n", iface_num, alt_set);
			} else {
				set_interface(fd, iface_index);
				debug("syz_usb_control_io: interface (%d, %d) set\n", iface_num, alt_set);
			}
		}

		response_length = event.ctrl.wLength;
	}

	struct usb_raw_ep_io_data response;
	response.inner.ep = 0;
	response.inner.flags = 0;
	if (response_length > sizeof(response.data))
		response_length = 0;
	if (event.ctrl.wLength < response_length)
		response_length = event.ctrl.wLength;
	if ((event.ctrl.bRequestType & USB_DIR_IN) && !event.ctrl.wLength) {
		// Something fishy is going on, try to read more data.
		response_length = USB_MAX_PACKET_SIZE;
	}
	response.inner.length = response_length;
	if (response_data)
		memcpy(&response.data[0], response_data, response_length);
	else
		memset(&response.data[0], 0, response_length);

	if ((event.ctrl.bRequestType & USB_DIR_IN) && event.ctrl.wLength) {
		debug("syz_usb_control_io: writing %d bytes\n", response.inner.length);
		debug_dump_data(&response.data[0], response.inner.length);
		rv = usb_raw_ep0_write(fd, (struct usb_raw_ep_io*)&response);
	} else {
		rv = usb_raw_ep0_read(fd, (struct usb_raw_ep_io*)&response);
		debug("syz_usb_control_io: read %d bytes\n", response.inner.length);
		debug_dump_data(&response.data[0], response.inner.length);
	}
	if (rv < 0) {
		debug("syz_usb_control_io: usb_raw_ep0_read/write failed with %d\n", rv);
		return rv;
	}

	sleep_ms(200);

	return 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_usb_ep_write
static volatile long syz_usb_ep_write(volatile long a0, volatile long a1, volatile long a2, volatile long a3)
{
	int fd = a0;
	uint16 ep = a1;
	uint32 len = a2;
	char* data = (char*)a3;

	struct usb_raw_ep_io_data io_data;
	io_data.inner.ep = ep;
	io_data.inner.flags = 0;
	if (len > sizeof(io_data.data))
		len = sizeof(io_data.data);
	io_data.inner.length = len;
	NONFAILING(memcpy(&io_data.data[0], data, len));

	int rv = usb_raw_ep_write(fd, (struct usb_raw_ep_io*)&io_data);
	if (rv < 0) {
		debug("syz_usb_ep_write: usb_raw_ep_write failed with %d\n", rv);
		return rv;
	}

	sleep_ms(200);

	return 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_usb_ep_read
static volatile long syz_usb_ep_read(volatile long a0, volatile long a1, volatile long a2, volatile long a3)
{
	int fd = a0;
	uint16 ep = a1;
	uint32 len = a2;
	char* data = (char*)a3;

	struct usb_raw_ep_io_data io_data;
	io_data.inner.ep = ep;
	io_data.inner.flags = 0;
	if (len > sizeof(io_data.data))
		len = sizeof(io_data.data);
	io_data.inner.length = len;

	int rv = usb_raw_ep_read(fd, (struct usb_raw_ep_io*)&io_data);
	if (rv < 0) {
		debug("syz_usb_ep_read: usb_raw_ep_read failed with %d\n", rv);
		return rv;
	}

	NONFAILING(memcpy(&data[0], &io_data.data[0], io_data.inner.length));

	debug("syz_usb_ep_read: received data:\n");
	debug_dump_data(&io_data.data[0], io_data.inner.length);

	sleep_ms(200);

	return 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_usb_disconnect
static volatile long syz_usb_disconnect(volatile long a0)
{
	int fd = a0;

	int rv = close(fd);

	sleep_ms(200);

	return rv;
}
#endif
