// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

// Linux-specific implementation of syz_usb_* pseudo-syscalls.

#include "common_usb.h"

#define UDC_NAME_LENGTH_MAX 128

struct usb_raw_init {
	__u8 driver_name[UDC_NAME_LENGTH_MAX];
	__u8 device_name[UDC_NAME_LENGTH_MAX];
	__u8 speed;
};

enum usb_raw_event_type {
	USB_RAW_EVENT_INVALID = 0,
	USB_RAW_EVENT_CONNECT = 1,
	USB_RAW_EVENT_CONTROL = 2,
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

#define USB_RAW_EPS_NUM_MAX 30
#define USB_RAW_EP_NAME_MAX 16
#define USB_RAW_EP_ADDR_ANY 0xff

struct usb_raw_ep_caps {
	__u32 type_control : 1;
	__u32 type_iso : 1;
	__u32 type_bulk : 1;
	__u32 type_int : 1;
	__u32 dir_in : 1;
	__u32 dir_out : 1;
};

struct usb_raw_ep_limits {
	__u16 maxpacket_limit;
	__u16 max_streams;
	__u32 reserved;
};

struct usb_raw_ep_info {
	__u8 name[USB_RAW_EP_NAME_MAX];
	__u32 addr;
	struct usb_raw_ep_caps caps;
	struct usb_raw_ep_limits limits;
};

struct usb_raw_eps_info {
	struct usb_raw_ep_info eps[USB_RAW_EPS_NUM_MAX];
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
#define USB_RAW_IOCTL_EPS_INFO _IOR('U', 11, struct usb_raw_eps_info)
#define USB_RAW_IOCTL_EP0_STALL _IO('U', 12)
#define USB_RAW_IOCTL_EP_SET_HALT _IOW('U', 13, __u32)
#define USB_RAW_IOCTL_EP_CLEAR_HALT _IOW('U', 14, __u32)
#define USB_RAW_IOCTL_EP_SET_WEDGE _IOW('U', 15, __u32)

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
#endif // SYZ_EXECUTOR || __NR_syz_usb_ep_write

#if SYZ_EXECUTOR || __NR_syz_usb_ep_read
static int usb_raw_ep_read(int fd, struct usb_raw_ep_io* io)
{
	return ioctl(fd, USB_RAW_IOCTL_EP_READ, io);
}
#endif // SYZ_EXECUTOR || __NR_syz_usb_ep_read

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

static int usb_raw_ep0_stall(int fd)
{
	return ioctl(fd, USB_RAW_IOCTL_EP0_STALL, 0);
}

#if SYZ_EXECUTOR || __NR_syz_usb_control_io
static int lookup_interface(int fd, uint8 bInterfaceNumber, uint8 bAlternateSetting)
{
	struct usb_device_index* index = lookup_usb_index(fd);
	if (!index)
		return -1;

	for (int i = 0; i < index->ifaces_num; i++) {
		if (index->ifaces[i].bInterfaceNumber == bInterfaceNumber &&
		    index->ifaces[i].bAlternateSetting == bAlternateSetting)
			return i;
	}
	return -1;
}
#endif // SYZ_EXECUTOR || __NR_syz_usb_control_io

#if SYZ_EXECUTOR || __NR_syz_usb_ep_write || __NR_syz_usb_ep_read
static int lookup_endpoint(int fd, uint8 bEndpointAddress)
{
	struct usb_device_index* index = lookup_usb_index(fd);
	if (!index)
		return -1;
	if (index->iface_cur < 0)
		return -1;

	for (int ep = 0; index->ifaces[index->iface_cur].eps_num; ep++)
		if (index->ifaces[index->iface_cur].eps[ep].desc.bEndpointAddress == bEndpointAddress)
			return index->ifaces[index->iface_cur].eps[ep].handle;
	return -1;
}
#endif // SYZ_EXECUTOR || __NR_syz_usb_ep_write || __NR_syz_usb_ep_read

static void set_interface(int fd, int n)
{
	struct usb_device_index* index = lookup_usb_index(fd);
	if (!index)
		return;

	if (index->iface_cur >= 0 && index->iface_cur < index->ifaces_num) {
		for (int ep = 0; ep < index->ifaces[index->iface_cur].eps_num; ep++) {
			int rv = usb_raw_ep_disable(fd, index->ifaces[index->iface_cur].eps[ep].handle);
			if (rv < 0) {
				debug("set_interface: failed to disable endpoint 0x%02x\n",
				      index->ifaces[index->iface_cur].eps[ep].desc.bEndpointAddress);
			} else {
				debug("set_interface: endpoint 0x%02x disabled\n",
				      index->ifaces[index->iface_cur].eps[ep].desc.bEndpointAddress);
			}
		}
	}
	if (n >= 0 && n < index->ifaces_num) {
		for (int ep = 0; ep < index->ifaces[n].eps_num; ep++) {
			int rv = usb_raw_ep_enable(fd, &index->ifaces[n].eps[ep].desc);
			if (rv < 0) {
				debug("set_interface: failed to enable endpoint 0x%02x\n",
				      index->ifaces[n].eps[ep].desc.bEndpointAddress);
			} else {
				debug("set_interface: endpoint 0x%02x enabled as %d\n",
				      index->ifaces[n].eps[ep].desc.bEndpointAddress, rv);
				index->ifaces[n].eps[ep].handle = rv;
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

#define USB_MAX_PACKET_SIZE 4096

struct usb_raw_control_event {
	struct usb_raw_event inner;
	struct usb_ctrlrequest ctrl;
	char data[USB_MAX_PACKET_SIZE];
};

struct usb_raw_ep_io_data {
	struct usb_raw_ep_io inner;
	char data[USB_MAX_PACKET_SIZE];
};

static volatile long syz_usb_connect_impl(uint64 speed, uint64 dev_len, const char* dev,
					  const struct vusb_connect_descriptors* descs,
					  lookup_connect_out_response_t lookup_connect_response_out)
{
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
	analyze_usb_device(index);
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

		char* response_data = NULL;
		uint32 response_length = 0;

		if (event.ctrl.bRequestType & USB_DIR_IN) {
			if (!lookup_connect_response_in(fd, descs, &event.ctrl, &response_data, &response_length)) {
				debug("syz_usb_connect: unknown request, stalling\n");
				usb_raw_ep0_stall(fd);
				continue;
			}
		} else {
			if (!lookup_connect_response_out(fd, descs, &event.ctrl, &done)) {
				debug("syz_usb_connect: unknown request, stalling\n");
				usb_raw_ep0_stall(fd);
				continue;
			}
			response_data = NULL;
			response_length = event.ctrl.wLength;
		}

		if ((event.ctrl.bRequestType & USB_TYPE_MASK) == USB_TYPE_STANDARD &&
		    event.ctrl.bRequest == USB_REQ_SET_CONFIGURATION) {
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

#if SYZ_EXECUTOR || __NR_syz_usb_connect
static volatile long syz_usb_connect(volatile long a0, volatile long a1, volatile long a2, volatile long a3)
{
	uint64 speed = a0;
	uint64 dev_len = a1;
	const char* dev = (const char*)a2;
	const struct vusb_connect_descriptors* descs = (const struct vusb_connect_descriptors*)a3;

	return syz_usb_connect_impl(speed, dev_len, dev, descs, &lookup_connect_response_out_generic);
}
#endif // SYZ_EXECUTOR || __NR_syz_usb_connect

#if SYZ_EXECUTOR || __NR_syz_usb_connect_ath9k
static volatile long syz_usb_connect_ath9k(volatile long a0, volatile long a1, volatile long a2, volatile long a3)
{
	uint64 speed = a0;
	uint64 dev_len = a1;
	const char* dev = (const char*)a2;
	const struct vusb_connect_descriptors* descs = (const struct vusb_connect_descriptors*)a3;

	return syz_usb_connect_impl(speed, dev_len, dev, descs, &lookup_connect_response_out_ath9k);
}
#endif // SYZ_EXECUTOR || __NR_syz_usb_connect_ath9k

#if SYZ_EXECUTOR || __NR_syz_usb_control_io
static volatile long syz_usb_control_io(volatile long a0, volatile long a1, volatile long a2)
{
	int fd = a0;
	const struct vusb_descriptors* descs = (const struct vusb_descriptors*)a1;
	const struct vusb_responses* resps = (const struct vusb_responses*)a2;

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

	char* response_data = NULL;
	uint32 response_length = 0;

	if ((event.ctrl.bRequestType & USB_DIR_IN) && event.ctrl.wLength) {
		if (!lookup_control_response(descs, resps, &event.ctrl, &response_data, &response_length)) {
			debug("syz_usb_connect: unknown request, stalling\n");
			usb_raw_ep0_stall(fd);
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
#endif // SYZ_EXECUTOR || __NR_syz_usb_control_io

#if SYZ_EXECUTOR || __NR_syz_usb_ep_write
static volatile long syz_usb_ep_write(volatile long a0, volatile long a1, volatile long a2, volatile long a3)
{
	int fd = a0;
	uint8 ep = a1;
	uint32 len = a2;
	char* data = (char*)a3;

	int ep_handle = lookup_endpoint(fd, ep);
	if (ep_handle < 0) {
		debug("syz_usb_ep_write: endpoint not found\n");
		return -1;
	}
	debug("syz_usb_ep_write: endpoint handle: %d\n", ep_handle);

	struct usb_raw_ep_io_data io_data;
	io_data.inner.ep = ep_handle;
	io_data.inner.flags = 0;
	if (len > sizeof(io_data.data))
		len = sizeof(io_data.data);
	io_data.inner.length = len;
	memcpy(&io_data.data[0], data, len);

	int rv = usb_raw_ep_write(fd, (struct usb_raw_ep_io*)&io_data);
	if (rv < 0) {
		debug("syz_usb_ep_write: usb_raw_ep_write failed with %d\n", rv);
		return rv;
	}

	sleep_ms(200);

	return 0;
}
#endif // SYZ_EXECUTOR || __NR_syz_usb_ep_write

#if SYZ_EXECUTOR || __NR_syz_usb_ep_read
static volatile long syz_usb_ep_read(volatile long a0, volatile long a1, volatile long a2, volatile long a3)
{
	int fd = a0;
	uint8 ep = a1;
	uint32 len = a2;
	char* data = (char*)a3;

	int ep_handle = lookup_endpoint(fd, ep);
	if (ep_handle < 0) {
		debug("syz_usb_ep_read: endpoint not found\n");
		return -1;
	}
	debug("syz_usb_ep_read: endpoint handle: %d\n", ep_handle);

	struct usb_raw_ep_io_data io_data;
	io_data.inner.ep = ep_handle;
	io_data.inner.flags = 0;
	if (len > sizeof(io_data.data))
		len = sizeof(io_data.data);
	io_data.inner.length = len;

	int rv = usb_raw_ep_read(fd, (struct usb_raw_ep_io*)&io_data);
	if (rv < 0) {
		debug("syz_usb_ep_read: usb_raw_ep_read failed with %d\n", rv);
		return rv;
	}

	memcpy(&data[0], &io_data.data[0], io_data.inner.length);

	debug("syz_usb_ep_read: received data:\n");
	debug_dump_data(&io_data.data[0], io_data.inner.length);

	sleep_ms(200);

	return 0;
}
#endif // SYZ_EXECUTOR || __NR_syz_usb_ep_read

#if SYZ_EXECUTOR || __NR_syz_usb_disconnect
static volatile long syz_usb_disconnect(volatile long a0)
{
	int fd = a0;

	int rv = close(fd);

	sleep_ms(200);

	return rv;
}
#endif // SYZ_EXECUTOR || __NR_syz_usb_disconnect
