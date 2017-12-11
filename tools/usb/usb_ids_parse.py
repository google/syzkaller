#!/usr/bin/python

"""
struct usb_device_id {
	/* which fields to match against? */
	__u16		match_flags;

	/* Used for product specific matches; range is inclusive */
	__u16		idVendor;
	__u16		idProduct;
	__u16		bcdDevice_lo;
	__u16		bcdDevice_hi;

	/* Used for device class matches */
	__u8		bDeviceClass;
	__u8		bDeviceSubClass;
	__u8		bDeviceProtocol;

	/* Used for interface class matches */
	__u8		bInterfaceClass;
	__u8		bInterfaceSubClass;
	__u8		bInterfaceProtocol;

	/* Used for vendor-specific interface matches */
	__u8		bInterfaceNumber;

	/* not matched against */
	kernel_ulong_t	driver_info
		__attribute__((aligned(sizeof(kernel_ulong_t))));
};
"""

USB_DEVICE_ID_MATCH_VENDOR		= 0x0001
USB_DEVICE_ID_MATCH_PRODUCT		= 0x0002
USB_DEVICE_ID_MATCH_DEV_LO		= 0x0004
USB_DEVICE_ID_MATCH_DEV_HI		= 0x0008
USB_DEVICE_ID_MATCH_DEV_CLASS		= 0x0010
USB_DEVICE_ID_MATCH_DEV_SUBCLASS	= 0x0020
USB_DEVICE_ID_MATCH_DEV_PROTOCOL	= 0x0040
USB_DEVICE_ID_MATCH_INT_CLASS		= 0x0080
USB_DEVICE_ID_MATCH_INT_SUBCLASS	= 0x0100
USB_DEVICE_ID_MATCH_INT_PROTOCOL	= 0x0200
USB_DEVICE_ID_MATCH_INT_NUMBER		= 0x0400

def print_device_id_struct(name, fields):
	match_flags = fields[0]
	idVendor = fields[1]
	idProduct = fields[2]
	bcdDevice_lo = fields[3]
	bcdDevice_hi = fields[4]
	bDeviceClass = fields[5]
	bDeviceSubClass = fields[6]
	bDeviceProtocol = fields[7]
	bIntClass = fields[8]
	bIntSubClass = fields[9]
	bIntProtocol = fields[10]
	bIntNumber = fields[11]

	def print_impl(flag, value, field, typ):
		if match_flags & flag:
			print '\t%s\t\tconst[0x%x, %s]' % (field, value, typ)
		else:
			print '\t%s\t\t%s' % (field, typ)

	print '%s {' % (name,)
	print_impl(USB_DEVICE_ID_MATCH_VENDOR, idVendor, 'idVendor', 'int16')
	print_impl(USB_DEVICE_ID_MATCH_PRODUCT, idProduct, 'idProduct', 'int16')
	dev_lo_bound = 0x0
	dev_hi_bound = 0xffff
	if match_flags & USB_DEVICE_ID_MATCH_DEV_LO:
		dev_lo_bound = bcdDevice_lo
	if match_flags & USB_DEVICE_ID_MATCH_DEV_HI:
		dev_hi_bound = bcdDevice_hi
	print '\tbcdDevice\t\tint16[0x%x:0x%x]' % (dev_lo_bound, dev_hi_bound)
	print_impl(USB_DEVICE_ID_MATCH_DEV_CLASS, bDeviceClass, 'bDeviceClass', 'int8')
	print_impl(USB_DEVICE_ID_MATCH_DEV_SUBCLASS, bDeviceSubClass, 'bDeviceSubClass', 'int8')
	print_impl(USB_DEVICE_ID_MATCH_DEV_PROTOCOL, bDeviceProtocol, 'bDeviceProtocol', 'int8')
	print_impl(USB_DEVICE_ID_MATCH_INT_CLASS, bIntClass, 'bIntClass', 'int8')
	print_impl(USB_DEVICE_ID_MATCH_INT_SUBCLASS, bIntSubClass, 'bIntSubClass', 'int8')
	print_impl(USB_DEVICE_ID_MATCH_INT_PROTOCOL, bIntProtocol, 'bIntProtocol', 'int8')
	print_impl(USB_DEVICE_ID_MATCH_INT_NUMBER, bIntNumber, 'bIntNumber', 'int8')
	print '}'

import sys
import string
import struct

data = None
with open(sys.argv[1]) as f:
	data = f.readlines()

for i in xrange(len(data)):
	line = data[i]
	line = line.strip()[:17*2]
	data[i] = line

for i, line in enumerate(data):
	s = struct.Struct('< H H H H H B B B B B B B')
	fields = s.unpack(line.decode('hex'))
	print_device_id_struct('usb_device_id_%04d' % (i,), fields)
	print ''

print """
usb_device_id_generic {
	idVendor	int16
	idProduct	int16
	bcdDevice	int16
	bDeviceClass	int8
	bDeviceSubClass	int8
	bDeviceProtocol	int8
	bIntClass	int8
	bIntSubClass	int8
	bIntProtocol	int8
	bIntNumber	int8
}
"""

print 'usb_device_id ['
for i in xrange(len(data)):
	print '\tid_%03d\t\t\tusb_device_id_%04d' % (i, i)
print '\tgeneric\t\t\tusb_device_id_generic'
print ']'
