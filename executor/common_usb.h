// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

// Generic parts of implementation of syz_usb_* pseudo-syscalls.

#define USB_MAX_IFACE_NUM 4
#define USB_MAX_EP_NUM 32
#define USB_MAX_FDS 6

struct usb_endpoint_index {
	// Copy of the endpoint descriptor:
	struct usb_endpoint_descriptor desc;
	// Raw Gadget endpoint handle used for this endpoint (Linux only):
	int handle;
};

struct usb_iface_index {
	// Pointer to where the original interface descriptor is stored:
	struct usb_interface_descriptor* iface;
	// Cached copied of some of the interface attributes:
	uint8 bInterfaceNumber;
	uint8 bAlternateSetting;
	uint8 bInterfaceClass;
	// Endpoint indexes:
	struct usb_endpoint_index eps[USB_MAX_EP_NUM];
	int eps_num;
};

struct usb_device_index {
	// Pointer to where the original descriptors are stored:
	struct usb_device_descriptor* dev;
	struct usb_config_descriptor* config;
	// Cached copied of some of the device attributes:
	uint8 bDeviceClass;
	uint8 bMaxPower;
	// Config and interface attributes/indexes:
	int config_length;
	struct usb_iface_index ifaces[USB_MAX_IFACE_NUM];
	int ifaces_num;
	int iface_cur;
};

struct usb_info {
	int fd;
	struct usb_device_index index;
};

static struct usb_info usb_devices[USB_MAX_FDS];
static int usb_devices_num;

static bool parse_usb_descriptor(const char* buffer, size_t length, struct usb_device_index* index)
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
				memcpy(&iface->eps[iface->eps_num].desc, buffer + offset, sizeof(iface->eps[iface->eps_num].desc));
				iface->eps_num++;
			}
		}
		offset += desc_length;
	}

	return true;
}

// add_usb_index() and lookup_usb_index() helper functions allow to store and lookup per-device metadata
// associated with a file descriptor that is used to comminicate with a particular emulated device.

static struct usb_device_index* add_usb_index(int fd, const char* dev, size_t dev_len)
{
	int i = __atomic_fetch_add(&usb_devices_num, 1, __ATOMIC_RELAXED);
	if (i >= USB_MAX_FDS)
		return NULL;

	if (!parse_usb_descriptor(dev, dev_len, &usb_devices[i].index))
		return NULL;

	__atomic_store_n(&usb_devices[i].fd, fd, __ATOMIC_RELEASE);
	return &usb_devices[i].index;
}

static struct usb_device_index* lookup_usb_index(int fd)
{
	for (int i = 0; i < USB_MAX_FDS; i++) {
		if (__atomic_load_n(&usb_devices[i].fd, __ATOMIC_ACQUIRE) == fd) {
			return &usb_devices[i].index;
		}
	}
	return NULL;
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

// A helper function that allows to see what kind of device is being emulated.
// Useful for debugging.
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

// A helper function that prints a request in readable form and returns whether descriptions for this
// request exist. Needs to be updated manually when new descriptions are added. Useful for debugging.
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

// lookup_connect_response_in() is a helper function that returns a response to a USB IN request
// based on syzkaller-generated arguments provided to syz_usb_connect* pseudo-syscalls. The data
// and its length to be used as a response are returned in *response_data and *response_length.
// The return value of this function lookup_connect_response_inindicates whether the request is known to syzkaller.

static bool lookup_connect_response_in(int fd, const struct vusb_connect_descriptors* descs,
				       const struct usb_ctrlrequest* ctrl,
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
				break;
			}
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	debug("lookup_connect_response_in: unknown request");
	return false;
}

// lookup_connect_response_out() functions process a USB OUT request and return in *done
// whether this is the last request that must be handled by syz_usb_connect* pseudo-syscalls.

typedef bool (*lookup_connect_out_response_t)(int fd, const struct vusb_connect_descriptors* descs,
					      const struct usb_ctrlrequest* ctrl, bool* done);

#if SYZ_EXECUTOR || __NR_syz_usb_connect
static bool lookup_connect_response_out_generic(int fd, const struct vusb_connect_descriptors* descs,
						const struct usb_ctrlrequest* ctrl, bool* done)
{
	switch (ctrl->bRequestType & USB_TYPE_MASK) {
	case USB_TYPE_STANDARD:
		switch (ctrl->bRequest) {
		case USB_REQ_SET_CONFIGURATION:
			*done = true;
			return true;
		default:
			break;
		}
		break;
	}

	debug("lookup_connect_response_out: unknown request");
	return false;
}
#endif // SYZ_EXECUTOR || __NR_syz_usb_connect

#if GOOS_linux && (SYZ_EXECUTOR || __NR_syz_usb_connect_ath9k)

// drivers/net/wireless/ath/ath9k/hif_usb.h
#define ATH9K_FIRMWARE_DOWNLOAD 0x30
#define ATH9K_FIRMWARE_DOWNLOAD_COMP 0x31

static bool lookup_connect_response_out_ath9k(int fd, const struct vusb_connect_descriptors* descs,
					      const struct usb_ctrlrequest* ctrl, bool* done)
{
	switch (ctrl->bRequestType & USB_TYPE_MASK) {
	case USB_TYPE_STANDARD:
		switch (ctrl->bRequest) {
		case USB_REQ_SET_CONFIGURATION:
			return true;
		default:
			break;
		}
		break;
	case USB_TYPE_VENDOR:
		switch (ctrl->bRequest) {
		case ATH9K_FIRMWARE_DOWNLOAD:
			return true;
		case ATH9K_FIRMWARE_DOWNLOAD_COMP:
			*done = true;
			return true;
		default:
			break;
		}
		break;
	}

	debug("lookup_connect_response_out_ath9k: unknown request");
	return false;
}

#endif // SYZ_EXECUTOR || __NR_syz_usb_connect_ath9k

#if GOOS_linux && (SYZ_EXECUTOR || __NR_syz_usb_control_io)

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

// lookup_control_response() is a helper function that returns a response to a USB IN request based
// on syzkaller-generated arguments provided to syz_usb_control_io* pseudo-syscalls. The data and its
// length to be used as a response are returned in *response_data and *response_length. The return
// value of this function indicates whether the response for this request is provided in
// syz_usb_control_io* arguments.

static bool lookup_control_response(const struct vusb_descriptors* descs, const struct vusb_responses* resps,
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

#endif // SYZ_EXECUTOR || __NR_syz_usb_control_io
