// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/google/syzkaller/prog"
)

const (
	USB_DEVICE_ID_MATCH_VENDOR = 1 << iota
	USB_DEVICE_ID_MATCH_PRODUCT
	USB_DEVICE_ID_MATCH_DEV_LO
	USB_DEVICE_ID_MATCH_DEV_HI
	USB_DEVICE_ID_MATCH_DEV_CLASS
	USB_DEVICE_ID_MATCH_DEV_SUBCLASS
	USB_DEVICE_ID_MATCH_DEV_PROTOCOL
	USB_DEVICE_ID_MATCH_INT_CLASS
	USB_DEVICE_ID_MATCH_INT_SUBCLASS
	USB_DEVICE_ID_MATCH_INT_PROTOCOL
	USB_DEVICE_ID_MATCH_INT_NUMBER

	BytesPerUsbID = 17
	BytesPerHidID = 12
)

type UsbDeviceID struct {
	MatchFlags         uint16
	IDVendor           uint16
	IDProduct          uint16
	BcdDeviceLo        uint16
	BcdDeviceHi        uint16
	BDeviceClass       uint8
	BDeviceSubClass    uint8
	BDeviceProtocol    uint8
	BInterfaceClass    uint8
	BInterfaceSubClass uint8
	BInterfaceProtocol uint8
	BInterfaceNumber   uint8
}

type HidDeviceID struct {
	Bus     uint16
	Group   uint16
	Vendor  uint32
	Product uint32
}

func (arch *arch) generateUsbDeviceDescriptor(g *prog.Gen, typ0 prog.Type, dir prog.Dir, old prog.Arg) (
	arg prog.Arg, calls []*prog.Call) {
	if old == nil {
		arg = g.GenerateSpecialArg(typ0, dir, &calls)
	} else {
		arg = old
		calls = g.MutateArg(arg)
	}
	if g.Target().ArgContainsAny(arg) {
		return
	}

	id := randUsbDeviceID(g)
	bcdDevice := id.BcdDeviceLo + uint16(g.Rand().Intn(int(id.BcdDeviceHi-id.BcdDeviceLo)+1))

	devArg := arg.(*prog.GroupArg).Inner[0]
	patchGroupArg(devArg, 7, "idVendor", uint64(id.IDVendor))
	patchGroupArg(devArg, 8, "idProduct", uint64(id.IDProduct))
	patchGroupArg(devArg, 9, "bcdDevice", uint64(bcdDevice))
	patchGroupArg(devArg, 3, "bDeviceClass", uint64(id.BDeviceClass))
	patchGroupArg(devArg, 4, "bDeviceSubClass", uint64(id.BDeviceSubClass))
	patchGroupArg(devArg, 5, "bDeviceProtocol", uint64(id.BDeviceProtocol))

	configArg := devArg.(*prog.GroupArg).Inner[14].(*prog.GroupArg).Inner[0].(*prog.GroupArg).Inner[0]
	interfacesArg := configArg.(*prog.GroupArg).Inner[8]

	for i, interfaceArg := range interfacesArg.(*prog.GroupArg).Inner {
		interfaceArg = interfaceArg.(*prog.GroupArg).Inner[0]
		if i > 0 {
			// Generate new IDs for every interface after the first one.
			id = randUsbDeviceID(g)
		}
		patchGroupArg(interfaceArg, 5, "bInterfaceClass", uint64(id.BInterfaceClass))
		patchGroupArg(interfaceArg, 6, "bInterfaceSubClass", uint64(id.BInterfaceSubClass))
		patchGroupArg(interfaceArg, 7, "bInterfaceProtocol", uint64(id.BInterfaceProtocol))
		patchGroupArg(interfaceArg, 2, "bInterfaceNumber", uint64(id.BInterfaceNumber))
	}

	return
}

func randUsbDeviceID(g *prog.Gen) UsbDeviceID {
	totalIds := len(usbIds) / BytesPerUsbID
	idNum := g.Rand().Intn(totalIds)
	base := usbIds[idNum*BytesPerUsbID : (idNum+1)*BytesPerUsbID]

	p := strings.NewReader(base)
	var id UsbDeviceID
	if binary.Read(p, binary.LittleEndian, &id) != nil {
		panic("not enough data to read")
	}

	if (id.MatchFlags & USB_DEVICE_ID_MATCH_VENDOR) == 0 {
		id.IDVendor = uint16(g.Rand().Intn(0xffff + 1))
	}
	if (id.MatchFlags & USB_DEVICE_ID_MATCH_PRODUCT) == 0 {
		id.IDProduct = uint16(g.Rand().Intn(0xffff + 1))
	}
	if (id.MatchFlags & USB_DEVICE_ID_MATCH_DEV_LO) == 0 {
		id.BcdDeviceLo = 0x0
	}
	if (id.MatchFlags & USB_DEVICE_ID_MATCH_DEV_HI) == 0 {
		id.BcdDeviceHi = 0xffff
	}
	if (id.MatchFlags & USB_DEVICE_ID_MATCH_DEV_CLASS) == 0 {
		id.BDeviceClass = uint8(g.Rand().Intn(0xff + 1))
	}
	if (id.MatchFlags & USB_DEVICE_ID_MATCH_DEV_SUBCLASS) == 0 {
		id.BDeviceSubClass = uint8(g.Rand().Intn(0xff + 1))
	}
	if (id.MatchFlags & USB_DEVICE_ID_MATCH_DEV_PROTOCOL) == 0 {
		id.BDeviceProtocol = uint8(g.Rand().Intn(0xff + 1))
	}
	if (id.MatchFlags & USB_DEVICE_ID_MATCH_INT_CLASS) == 0 {
		id.BInterfaceClass = uint8(g.Rand().Intn(0xff + 1))
	}
	if (id.MatchFlags & USB_DEVICE_ID_MATCH_INT_SUBCLASS) == 0 {
		id.BInterfaceSubClass = uint8(g.Rand().Intn(0xff + 1))
	}
	if (id.MatchFlags & USB_DEVICE_ID_MATCH_INT_PROTOCOL) == 0 {
		id.BInterfaceProtocol = uint8(g.Rand().Intn(0xff + 1))
	}
	if (id.MatchFlags & USB_DEVICE_ID_MATCH_INT_NUMBER) == 0 {
		id.BInterfaceNumber = uint8(g.Rand().Intn(0xff + 1))
	}

	return id
}

func (arch *arch) generateUsbHidDeviceDescriptor(g *prog.Gen, typ0 prog.Type, dir prog.Dir, old prog.Arg) (
	arg prog.Arg, calls []*prog.Call) {
	if old == nil {
		arg = g.GenerateSpecialArg(typ0, dir, &calls)
	} else {
		arg = old
		calls = g.MutateArg(arg)
	}
	if g.Target().ArgContainsAny(arg) {
		return
	}

	totalIds := len(hidIds) / BytesPerHidID
	idNum := g.Rand().Intn(totalIds)
	base := hidIds[idNum*BytesPerHidID : (idNum+1)*BytesPerHidID]

	p := strings.NewReader(base)
	var id HidDeviceID
	if binary.Read(p, binary.LittleEndian, &id) != nil {
		panic("not enough data to read")
	}

	devArg := arg.(*prog.GroupArg).Inner[0]
	patchGroupArg(devArg, 7, "idVendor", uint64(id.Vendor))
	patchGroupArg(devArg, 8, "idProduct", uint64(id.Product))

	return
}

func patchGroupArg(arg prog.Arg, index int, field string, value uint64) {
	a := arg.(*prog.GroupArg)
	typ := a.Type().(*prog.StructType)
	if field != typ.Fields[index].Name {
		panic(fmt.Sprintf("bad field, expected %v, found %v", field, typ.Fields[index].Name))
	}
	a.Inner[index].(*prog.ConstArg).Val = value
}
