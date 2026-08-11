---
name: usb
description: USB Device Emulation and Gadget Constraints (raw-gadget/dummy_hcd)
---
# USB Device Emulation (raw-gadget / dummy_hcd)
- Connect Device: Use 'syz_usb_connect(speed, dev_len, dev, conn)' (or 'syz_usb_connect_ath9k').
  * 'speed': 0x0 (Full), 0x1 (High), 0x2 (Super).
  * 'dev': USB descriptors. Pass complex nested structs using ANY squashing:
    &(0x7f0000000040)=ANY=[@ANYBLOB="120100..."].
- Control Transfer: Use 'syz_usb_control_io(conn, req, res)'.
- Endpoint I/O: Use 'syz_usb_ep_write(conn, ep, len, data)' or 'syz_usb_ep_read(conn, ep, len, data)'
  (e.g. ep 0x81 IN / 0x02 OUT) to exchange data packets with the emulated device.
- Disconnect: Use 'syz_usb_disconnect(conn)'.
