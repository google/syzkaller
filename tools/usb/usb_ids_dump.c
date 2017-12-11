#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/usb/ch9.h>
#include <linux/usb/gadgetfs.h>
#include <linux/usbdevice_fs.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define USBFUZZ_SETUP 100
#define USBFUZZ_RUN 101

struct usbfuzz_setup_cmd {
	int64_t speed;
	int64_t length;
	char* device;
	char* desc_responses;
	char* req_responses;
	char* gen_responses;
};

void syz_usb_connect(int64_t speed, int64_t length, char *device) {
	uint64_t null = 0;

	int fd = open("/sys/kernel/debug/usbfuzz", O_RDWR);
	if (fd < 0)
		return;

	struct usbfuzz_setup_cmd cmd;
	cmd.speed = speed;
	cmd.length = length;
	cmd.device = device;
	cmd.desc_responses = (char *)&null;
	cmd.req_responses = (char *)&null;
	cmd.gen_responses = (char *)&null;
	ioctl(fd, USBFUZZ_SETUP, &cmd);

	ioctl(fd, USBFUZZ_RUN, 0);

	sleep(10);
}

int main() {
	char buffer[2048];
	memset(&buffer[0], 0, 2048);

	struct usb_device_descriptor *dev =
		(struct usb_device_descriptor *)&buffer[0];
	struct usb_config_descriptor *config =
		(struct usb_config_descriptor *)(&buffer[0] + sizeof(*dev));
	struct usb_interface_descriptor *iface =
		(struct usb_interface_descriptor *)(&buffer[0] + sizeof(*dev) + sizeof(*config));

	int64_t length = sizeof(*dev) + sizeof(*config) * sizeof(*iface);

	dev->bLength = USB_DT_DEVICE_SIZE;
	dev->bDescriptorType = USB_DT_DEVICE;
	dev->bcdUSB = 0;
	dev->bDeviceClass = 0;
	dev->bDeviceSubClass = 0;
	dev->bDeviceProtocol = 0;
	dev->bMaxPacketSize0 = 0x40;
	dev->idVendor = 0x4242;
	dev->idProduct = 0x4242;
	dev->bcdDevice = 0;
	dev->iManufacturer = 0;
	dev->iProduct = 0;
	dev->iSerialNumber = 0;
	dev->bNumConfigurations = 1;

	config->bLength = USB_DT_CONFIG_SIZE;
	config->bDescriptorType = USB_DT_CONFIG;
	config->wTotalLength = sizeof(*config) + sizeof(*iface);
	config->bNumInterfaces = 1;
	config->bConfigurationValue = 0;
	config->iConfiguration = 0;
	config->bmAttributes = 0;
	config->bMaxPower = 0;

	iface->bLength = USB_DT_INTERFACE_SIZE;
	iface->bDescriptorType = USB_DT_INTERFACE;
	iface->bInterfaceNumber = 0;
	iface->bAlternateSetting = 0;
	iface->bNumEndpoints = 0;
	iface->bInterfaceClass = 0;
	iface->bInterfaceSubClass = 0;
	iface->bInterfaceProtocol = 0;
	iface->iInterface = 0;

	syz_usb_connect(USB_SPEED_FULL, length, &buffer[0]);

	return 0;
}
