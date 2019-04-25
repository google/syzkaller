// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

// Implementation of syz_usb_* pseudo-syscalls.

#define USB_MAX_EP_NUM 32

struct usb_device_index {
	struct usb_device_descriptor* dev;
	struct usb_config_descriptor* config;
	unsigned config_length;
	struct usb_interface_descriptor* iface;
	struct usb_endpoint_descriptor* eps[USB_MAX_EP_NUM];
	unsigned eps_num;
};

static bool parse_usb_descriptor(char* buffer, size_t length, struct usb_device_index* index)
{
	if (length < sizeof(*index->dev) + sizeof(*index->config) + sizeof(*index->iface))
		return false;

	index->dev = (struct usb_device_descriptor*)buffer;
	index->config = (struct usb_config_descriptor*)(buffer + sizeof(*index->dev));
	index->config_length = length - sizeof(*index->dev);
	index->iface = (struct usb_interface_descriptor*)(buffer + sizeof(*index->dev) + sizeof(*index->config));

	index->eps_num = 0;
	size_t offset = 0;

	while (true) {
		if (offset == length)
			break;
		if (offset + 1 < length)
			break;
		uint8 length = buffer[offset];
		uint8 type = buffer[offset + 1];
		if (type == USB_DT_ENDPOINT) {
			index->eps[index->eps_num] = (struct usb_endpoint_descriptor*)(buffer + offset);
			index->eps_num++;
		}
		if (index->eps_num == USB_MAX_EP_NUM)
			break;
		offset += length;
	}

	return true;
}

enum usb_fuzzer_event_type {
	USB_FUZZER_EVENT_INVALID,
	USB_FUZZER_EVENT_CONNECT,
	USB_FUZZER_EVENT_DISCONNECT,
	USB_FUZZER_EVENT_SUSPEND,
	USB_FUZZER_EVENT_RESUME,
	USB_FUZZER_EVENT_CONTROL,
};

struct usb_fuzzer_event {
	uint32 type;
	uint32 length;
	char data[0];
};

struct usb_fuzzer_init {
	uint64 speed;
	const char* driver_name;
	const char* device_name;
};

struct usb_fuzzer_ep_io {
	uint16 ep;
	uint16 flags;
	uint32 length;
	char data[0];
};

#define USB_FUZZER_IOCTL_INIT _IOW('U', 0, struct usb_fuzzer_init)
#define USB_FUZZER_IOCTL_RUN _IO('U', 1)
#define USB_FUZZER_IOCTL_EP0_READ _IOWR('U', 2, struct usb_fuzzer_event)
#define USB_FUZZER_IOCTL_EP0_WRITE _IOW('U', 3, struct usb_fuzzer_ep_io)
#define USB_FUZZER_IOCTL_EP_ENABLE _IOW('U', 4, struct usb_endpoint_descriptor)
#define USB_FUZZER_IOCTL_EP_WRITE _IOW('U', 6, struct usb_fuzzer_ep_io)
#define USB_FUZZER_IOCTL_CONFIGURE _IO('U', 8)
#define USB_FUZZER_IOCTL_VBUS_DRAW _IOW('U', 9, uint32)

int usb_fuzzer_open()
{
	return open("/sys/kernel/debug/usb-fuzzer", O_RDWR);
}

int usb_fuzzer_init(int fd, uint32 speed, const char* driver, const char* device)
{
	struct usb_fuzzer_init arg;
	arg.speed = speed;
	arg.driver_name = driver;
	arg.device_name = device;
	return ioctl(fd, USB_FUZZER_IOCTL_INIT, &arg);
}

int usb_fuzzer_run(int fd)
{
	return ioctl(fd, USB_FUZZER_IOCTL_RUN, 0);
}

int usb_fuzzer_ep0_read(int fd, struct usb_fuzzer_event* event)
{
	return ioctl(fd, USB_FUZZER_IOCTL_EP0_READ, event);
}

int usb_fuzzer_ep0_write(int fd, struct usb_fuzzer_ep_io* io)
{
	return ioctl(fd, USB_FUZZER_IOCTL_EP0_WRITE, io);
}

int usb_fuzzer_ep_write(int fd, struct usb_fuzzer_ep_io* io)
{
	return ioctl(fd, USB_FUZZER_IOCTL_EP_WRITE, io);
}

int usb_fuzzer_ep_enable(int fd, struct usb_endpoint_descriptor* desc)
{
	return ioctl(fd, USB_FUZZER_IOCTL_EP_ENABLE, desc);
}

int usb_fuzzer_configure(int fd)
{
	return ioctl(fd, USB_FUZZER_IOCTL_CONFIGURE, 0);
}

int usb_fuzzer_vbus_draw(int fd, uint32 power)
{
	return ioctl(fd, USB_FUZZER_IOCTL_VBUS_DRAW, power);
}

#define USB_MAX_PACKET_SIZE 1024

struct usb_fuzzer_control_event {
	struct usb_fuzzer_event inner;
	struct usb_ctrlrequest ctrl;
};

struct usb_fuzzer_ep_io_data {
	struct usb_fuzzer_ep_io inner;
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

static bool lookup_connect_response(struct vusb_connect_descriptors* descs, struct usb_device_index* index,
				    struct usb_ctrlrequest* ctrl, char** response_data, uint32* response_length, bool* done)
{
	uint8 str_idx;

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
				if (str_idx >= descs->strs_len)
					return false;
				*response_data = descs->strs[str_idx].str;
				*response_length = descs->strs[str_idx].len;
				return true;
			case USB_DT_BOS:
				*response_data = descs->bos;
				*response_length = descs->bos_len;
				return true;
			case USB_DT_DEVICE_QUALIFIER:
				*response_data = descs->qual;
				*response_length = descs->qual_len;
				return true;
			default:
				fail("syz_usb_connect: no response");
				return false;
			}
			break;
		case USB_REQ_SET_CONFIGURATION:
			*response_length = 0;
			*response_data = NULL;
			*done = true;
			return true;
		default:
			fail("syz_usb_connect: no response");
			return false;
		}
		break;
	default:
		fail("syz_usb_connect: no response");
		return false;
	}

	return false;
}

static volatile long syz_usb_connect(volatile long a0, volatile long a1, volatile long a2, volatile long a3)
{
	int64_t speed = a0;
	int64_t dev_len = a1;
	char* dev = (char*)a2;
	struct vusb_connect_descriptors* descs = (struct vusb_connect_descriptors*)a3;

	debug("syz_usb_connect: dev: %p\n", dev);
	if (!dev)
		return -1;

	debug("syz_usb_connect: device data:\n");
	debug_dump_data(dev, dev_len);

	struct usb_device_index index;
	memset(&index, 0, sizeof(index));
	int rv = false;
	NONFAILING(rv = parse_usb_descriptor(dev, dev_len, &index));
	if (!rv)
		return -1;
	debug("syz_usb_connect: parsed usb descriptor\n");

	int fd = usb_fuzzer_open();
	if (fd < 0)
		return -1;
	debug("syz_usb_connect: usb_fuzzer_open success\n");

	char device[32];
	sprintf(&device[0], "dummy_udc.%llu", procid);
	rv = usb_fuzzer_init(fd, speed, "dummy_udc", &device[0]);
	if (rv < 0)
		return -1;
	debug("syz_usb_connect: usb_fuzzer_init success\n");

	rv = usb_fuzzer_run(fd);
	if (rv < 0)
		return -1;
	debug("syz_usb_connect: usb_fuzzer_run success\n");

	bool done = false;
	while (!done) {
		struct usb_fuzzer_control_event event;
		event.inner.type = 0;
		event.inner.length = sizeof(event.ctrl);
		rv = usb_fuzzer_ep0_read(fd, (struct usb_fuzzer_event*)&event);
		if (rv < 0)
			return -1;
		if (event.inner.type != USB_FUZZER_EVENT_CONTROL)
			continue;

		debug("syz_usb_connect: bRequestType: 0x%x, bRequest: 0x%x, wValue: 0x%x, wIndex: 0x%x, wLength: %d\n",
		      event.ctrl.bRequestType, event.ctrl.bRequest, event.ctrl.wValue, event.ctrl.wIndex, event.ctrl.wLength);

		bool response_found = false;
		char* response_data = NULL;
		uint32 response_length = 0;
		NONFAILING(response_found = lookup_connect_response(descs, &index, &event.ctrl, &response_data, &response_length, &done));
		if (!response_found)
			return -1;

		if (done) {
			int rv = usb_fuzzer_vbus_draw(fd, index.config->bMaxPower);
			if (rv < 0)
				return -1;
			rv = usb_fuzzer_configure(fd);
			if (rv < 0)
				return -1;
			unsigned ep;
			for (ep = 0; ep < index.eps_num; ep++) {
				rv = usb_fuzzer_ep_enable(fd, index.eps[ep]);
				if (rv < 0)
					fail("syz_usb_connect: ep enable failed");
			}
		}

		struct usb_fuzzer_ep_io_data response;
		response.inner.ep = 0;
		response.inner.flags = 0;
		if (response_length > sizeof(response.data))
			response_length = 0;
		response.inner.length = response_length;
		if (response_data)
			memcpy(&response.data[0], response_data, response_length);
		if (event.ctrl.wLength < response.inner.length)
			response.inner.length = event.ctrl.wLength;
		debug("syz_usb_connect: reply length = %d\n", response.inner.length);
		usb_fuzzer_ep0_write(fd, (struct usb_fuzzer_ep_io*)&response);
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

static bool lookup_control_io_response(struct vusb_descriptors* descs, struct vusb_responses* resps,
				       struct usb_ctrlrequest* ctrl, char** response_data, uint32* response_length)
{
	int descs_num = (descs->len - offsetof(struct vusb_descriptors, descs)) / sizeof(descs->descs[0]);
	int resps_num = (resps->len - offsetof(struct vusb_responses, resps)) / sizeof(resps->resps[0]);

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

		if (descs->generic) {
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

		if (resps->generic) {
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

	struct usb_fuzzer_control_event event;
	event.inner.type = 0;
	event.inner.length = sizeof(event.ctrl);
	int rv = usb_fuzzer_ep0_read(fd, (struct usb_fuzzer_event*)&event);
	if (rv < 0)
		return -1;
	if (event.inner.type != USB_FUZZER_EVENT_CONTROL)
		return -1;

	debug("syz_usb_control_io: bRequestType: 0x%x, bRequest: 0x%x, wValue: 0x%x, wIndex: 0x%x, wLength: %d\n",
	      event.ctrl.bRequestType, event.ctrl.bRequest, event.ctrl.wValue, event.ctrl.wIndex, event.ctrl.wLength);

	bool response_found = false;
	char* response_data = NULL;
	uint32 response_length = 0;
	NONFAILING(response_found = lookup_control_io_response(descs, resps, &event.ctrl, &response_data, &response_length));
	if (!response_found)
		return -1;

	struct usb_fuzzer_ep_io_data response;
	response.inner.ep = 0;
	response.inner.flags = 0;
	if (response_length > sizeof(response.data))
		response_length = 0;
	response.inner.length = response_length;
	if (response_data)
		memcpy(&response.data[0], response_data, response_length);
	if (event.ctrl.wLength < response.inner.length)
		response.inner.length = event.ctrl.wLength;
	debug("syz_usb_control_io: response length = %d\n", response.inner.length);
	usb_fuzzer_ep0_write(fd, (struct usb_fuzzer_ep_io*)&response);

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

	struct usb_fuzzer_ep_io_data response;
	response.inner.ep = ep;
	response.inner.flags = 0;
	if (len > sizeof(response.data))
		len = 0;
	response.inner.length = len;
	if (data)
		memcpy(&response.data[0], data, len);

	return usb_fuzzer_ep_write(fd, (struct usb_fuzzer_ep_io*)&response);
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
