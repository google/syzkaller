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
		arg = prog.CloneArg(old)
		calls = g.MutateArg(arg)
	}
	if g.Target().ArgContainsAny(arg) {
		return
	}

	patchUsbDeviceID(g, &arg, calls, usbIdsAll, true)

	return
}

func (arch *arch) generateUsbPrinterDeviceDescriptor(g *prog.Gen, typ0 prog.Type, dir prog.Dir, old prog.Arg) (
	arg prog.Arg, calls []*prog.Call) {
	if old == nil {
		arg = g.GenerateSpecialArg(typ0, dir, &calls)
	} else {
		arg = prog.CloneArg(old)
		calls = g.MutateArg(arg)
	}
	if g.Target().ArgContainsAny(arg) {
		return
	}

	// Roll the dice to decide if and how we want to patch printer USB IDs.
	switch {
	case g.Rand().Intn(3) == 0:
		// Syzlang descriptions already contain passable IDs, leave them as is.
		return
	case g.Rand().Intn(2) == 0:
		// Patch in quirk IDs that are hardcoded in the USB printer class driver
		// (and thus are not auto-extractable) to allow exercising driver quirks;
		// see quirk_printers in drivers/usb/class/usblp.c.
		var idVendor int16
		var idProduct int16
		if g.Rand().Intn(2) == 0 { // USBLP_QUIRK_BIDIR
			idVendor = 0x03f0
			idProduct = 0x0004
		} else { // USBLP_QUIRK_BAD_CLASS
			idVendor = 0x04b8
			idProduct = 0x0202
		}
		devArg := arg.(*prog.GroupArg).Inner[0]
		patchGroupArg(devArg, 7, "idVendor", uint64(idVendor))
		patchGroupArg(devArg, 8, "idProduct", uint64(idProduct))
	default:
		// Patch in IDs auto-extracted from the matching rules for the USB printer class.
		// Do not patch IDs that are not used in the matching rules to avoid subverting
		// the kernel into matching the device to a different driver.
		if ids, ok := usbIds["usblp"]; ok {
			patchUsbDeviceID(g, &arg, calls, ids, false)
		}
	}

	return
}

// audioQuirksIDs contains quirk IDs that are hardcoded in the USB audio class drivers
// (and thus are not auto-extractable) to allow exercising driver quirks.
var audioQuirksIDs = [][2]uint16{
	// sound/usb/quirks.c
	{0x10f5, 0x0200},
	{0x0d8c, 0x0102},
	{0x0ccd, 0x00b1},
	{0x1235, 0x0010},
	{0x1235, 0x0018},
	{0x0763, 0x2012},
	{0x047f, 0xc010},
	{0x2466, 0x8010},
	// sound/usb/stream.c
	{0x04fa, 0x4201},
	{0x0763, 0x2003},
	// sound/usb/midi.c
	{0x0a67, 0x5011},
	{0x0a92, 0x1020},
	{0x1430, 0x474b},
	{0x15ca, 0x0101},
	{0x15ca, 0x1806},
	{0x1a86, 0x752d},
	{0xfc08, 0x0101},
	{0x0644, 0x800e},
	{0x0644, 0x800f},
	{0x0763, 0x0150},
	{0x0499, 0x105c},
	{0x0582, 0x0000},
	{0x0582, 0x0003},
	{0x0582, 0x0004},
	{0x0582, 0x0007},
	{0x0582, 0x000b},
	{0x0582, 0x000c},
	{0x0582, 0x0014},
	{0x0582, 0x0016},
	{0x0582, 0x0023},
	{0x0582, 0x0027},
	{0x0582, 0x0029},
	{0x0582, 0x002b},
	{0x0582, 0x002f},
	{0x0582, 0x0033},
	{0x0582, 0x003b},
	{0x0582, 0x0048},
	{0x0582, 0x004d},
	{0x0582, 0x0089},
	{0x0582, 0x009a},
	{0x0582, 0x00b2},
	{0x0582, 0x00eb},
	{0x0582, 0x0102},
	{0x0582, 0x010f},
	{0x0582, 0x0114},
	{0x0582, 0x0120},
	{0x0582, 0x0121},
	{0x0582, 0x0145},
	{0x0582, 0x0156},
	{0x0582, 0x015b},
	{0x0763, 0x1031},
	{0x0763, 0x1033},
	{0x07fd, 0x0001},
	{0x086a, 0x0001},
	{0x086a, 0x0002},
	{0x086a, 0x0003},
	{0x09e8, 0x0062},
	{0x133e, 0x0815},
	// sound/usb/card.c
	{0x18d1, 0x2d04},
	{0x18d1, 0x2d05},
	// sound/usb/format.c
	{0x0582, 0x0016},
	{0x0582, 0x000c},
	{0x0d8c, 0x0201},
	{0x0d8c, 0x0078},
	{0x041e, 0x4064},
	{0x041e, 0x4068},
	{0x0e41, 0x4241},
	{0x0e41, 0x4242},
	{0x0e41, 0x4244},
	{0x0e41, 0x4246},
	{0x0e41, 0x4247},
	{0x0e41, 0x4248},
	{0x0e41, 0x4249},
	{0x0e41, 0x424a},
	{0x19f7, 0x0011},
	{0x0e41, 0x3000},
	{0x0e41, 0x3020},
	{0x0e41, 0x3061},
	// sound/usb/mixer_quirks.c
	{0x041e, 0x3000},
	{0x041e, 0x3020},
	{0x041e, 0x3040},
	{0x041e, 0x3042},
	{0x041e, 0x3048},
	{0x041e, 0x30df},
	{0x041e, 0x3237},
	{0x041e, 0x323b},
	{0x041e, 0x3263},
	{0x0644, 0x8047},
	{0x0b05, 0x1739},
	{0x0b05, 0x1743},
	{0x0b05, 0x17a0},
	{0x0bda, 0x4014},
	{0x0d8c, 0x000c},
	{0x0d8c, 0x0014},
	{0x0d8c, 0x0103},
	{0x1235, 0x8002},
	{0x1235, 0x8004},
	{0x1235, 0x800c},
	{0x1235, 0x8012},
	{0x1235, 0x8014},
	{0x1235, 0x8201},
	{0x1235, 0x8203},
	{0x1235, 0x8204},
	{0x1235, 0x8210},
	{0x1235, 0x8211},
	{0x1235, 0x8212},
	{0x1235, 0x8213},
	{0x1235, 0x8214},
	{0x1235, 0x8215},
	{0x17cc, 0x1011},
	{0x17cc, 0x1021},
	{0x194f, 0x010c},
	{0x200c, 0x1018},
	{0x21b4, 0x0081},
	{0x2a39, 0x3fb0},
	{0x2a39, 0x3fd2},
	{0x2a39, 0x3fd3},
	{0x2a39, 0x3fd4},
}

func (arch *arch) generateAudioDeviceDescriptor(g *prog.Gen, typ0 prog.Type, dir prog.Dir, old prog.Arg) (
	arg prog.Arg, calls []*prog.Call) {
	if old == nil {
		arg = g.GenerateSpecialArg(typ0, dir, &calls)
	} else {
		arg = prog.CloneArg(old)
		calls = g.MutateArg(arg)
	}
	if g.Target().ArgContainsAny(arg) {
		return
	}
	// Roll the dice to decide if and how we want to patch audio device IDs.
	switch {
	case g.Rand().Intn(3) == 0:
		// Syzlang descriptions already contain passable IDs, leave them as is.
		return
	case g.Rand().Intn(2) == 0:
		// Patch in quirk IDs that are hardcoded in the USB audio class drivers
		// (and thus are not auto-extractable) to allow exercising driver quirks.
		idx := g.Rand().Intn(len(audioQuirksIDs))
		idVendor := audioQuirksIDs[idx][0]
		idProduct := audioQuirksIDs[idx][1]
		devArg := arg.(*prog.GroupArg).Inner[0]
		patchGroupArg(devArg, 7, "idVendor", uint64(idVendor))
		patchGroupArg(devArg, 8, "idProduct", uint64(idProduct))
	default:
		// Patch in IDs auto-extracted from the matching rules for the USB audio class.
		// Do not patch IDs that are not used in the matching rules to avoid subverting
		// the kernel into matching the device to a different driver.
		var ids string
		for _, name := range []string{
			"snd-bcd2000",
			"snd-ua101",
			"snd-usb-6fire",
			"snd-usb-audio",
			"snd-usb-caiaq",
			"snd-usb-hiface",
			"snd-usb-us122l",
			"snd-usb-usx2y",
			"snd_usb_pod",
			"snd_usb_podhd",
			"snd_usb_toneport",
			"snd_usb_variax",
		} {
			if driverIDs, ok := usbIds[name]; ok {
				ids += driverIDs
			}
		}
		if ids != "" {
			patchUsbDeviceID(g, &arg, calls, ids, false)
		}
	}
	return
}

func patchUsbDeviceID(g *prog.Gen, arg *prog.Arg, calls []*prog.Call, ids string, patchNonMatching bool) {
	id := randUsbDeviceID(g, ids, patchNonMatching)

	devArg := (*arg).(*prog.GroupArg).Inner[0]
	if (id.MatchFlags&USB_DEVICE_ID_MATCH_VENDOR) != 0 || patchNonMatching {
		patchGroupArg(devArg, 7, "idVendor", uint64(id.IDVendor))
	}
	if (id.MatchFlags&USB_DEVICE_ID_MATCH_PRODUCT) != 0 || patchNonMatching {
		patchGroupArg(devArg, 8, "idProduct", uint64(id.IDProduct))
	}
	if (id.MatchFlags&USB_DEVICE_ID_MATCH_DEV_LO) != 0 ||
		(id.MatchFlags&USB_DEVICE_ID_MATCH_DEV_HI) != 0 || patchNonMatching {
		bcdDevice := id.BcdDeviceLo + uint16(g.Rand().Intn(int(id.BcdDeviceHi-id.BcdDeviceLo)+1))
		patchGroupArg(devArg, 9, "bcdDevice", uint64(bcdDevice))
	}
	if (id.MatchFlags&USB_DEVICE_ID_MATCH_DEV_CLASS) != 0 || patchNonMatching {
		patchGroupArg(devArg, 3, "bDeviceClass", uint64(id.BDeviceClass))
	}
	if (id.MatchFlags&USB_DEVICE_ID_MATCH_DEV_SUBCLASS) != 0 || patchNonMatching {
		patchGroupArg(devArg, 4, "bDeviceSubClass", uint64(id.BDeviceSubClass))
	}
	if (id.MatchFlags&USB_DEVICE_ID_MATCH_DEV_PROTOCOL) != 0 || patchNonMatching {
		patchGroupArg(devArg, 5, "bDeviceProtocol", uint64(id.BDeviceProtocol))
	}

	configArg := devArg.(*prog.GroupArg).Inner[14].(*prog.GroupArg).Inner[0].(*prog.GroupArg).Inner[0]
	interfacesArg := configArg.(*prog.GroupArg).Inner[9]

	for i, interfaceArg := range interfacesArg.(*prog.GroupArg).Inner {
		interfaceArg = interfaceArg.(*prog.GroupArg).Inner[0]
		if i > 0 {
			// Generate new IDs for every interface after the first one.
			id = randUsbDeviceID(g, ids, patchNonMatching)
		}
		if (id.MatchFlags&USB_DEVICE_ID_MATCH_DEV_CLASS) != 0 || patchNonMatching {
			patchGroupArg(interfaceArg, 5, "bInterfaceClass", uint64(id.BInterfaceClass))
		}
		if (id.MatchFlags&USB_DEVICE_ID_MATCH_DEV_SUBCLASS) != 0 || patchNonMatching {
			patchGroupArg(interfaceArg, 6, "bInterfaceSubClass", uint64(id.BInterfaceSubClass))
		}
		if (id.MatchFlags&USB_DEVICE_ID_MATCH_DEV_PROTOCOL) != 0 || patchNonMatching {
			patchGroupArg(interfaceArg, 7, "bInterfaceProtocol", uint64(id.BInterfaceProtocol))
		}
		if (id.MatchFlags&USB_DEVICE_ID_MATCH_INT_NUMBER) != 0 || patchNonMatching {
			patchGroupArg(interfaceArg, 2, "bInterfaceNumber", uint64(id.BInterfaceNumber))
		}
	}
}

func randUsbDeviceID(g *prog.Gen, ids string, patchNonMatching bool) UsbDeviceID {
	totalIds := len(ids) / BytesPerUsbID
	idNum := g.Rand().Intn(totalIds)
	base := ids[idNum*BytesPerUsbID : (idNum+1)*BytesPerUsbID]

	p := strings.NewReader(base)
	var id UsbDeviceID
	if binary.Read(p, binary.LittleEndian, &id) != nil {
		panic("not enough data to read")
	}

	// Don't generate values for IDs that won't be patched in.
	if !patchNonMatching {
		return id
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
		arg = prog.CloneArg(old)
		calls = g.MutateArg(arg)
	}
	if g.Target().ArgContainsAny(arg) {
		return
	}

	totalIds := len(hidIdsAll) / BytesPerHidID
	idNum := g.Rand().Intn(totalIds)
	base := hidIdsAll[idNum*BytesPerHidID : (idNum+1)*BytesPerHidID]

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
