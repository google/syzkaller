---
name: usb
description: USB Device Emulation and Gadget Constraints (raw-gadget/dummy_hcd)
---
# USB Device Emulation (raw-gadget / dummy_hcd)
- Connect Device: Use 'syz_usb_connect(speed, dev_len, dev, conn)' (or 'syz_usb_connect_ath9k').
  * 'speed': 0x0 (Full), 0x1 (High), 0x2 (Super).
  * 'dev': USB descriptors. Pass complex nested structs using ANY squashing:
    &(0x7f0000000040)=ANY=[@ANYBLOB="120100..."].
- Asynchronous Driver Probe Rule: Device enumeration runs asynchronously in background kernel threads (hub_wq).
  To prevent race conditions, you MUST insert a sleep delay (e.g. 'nanosleep(&(0x7f0000000300)={0, 50000000}, 0)')
  immediately after 'syz_usb_connect' before calling openat or ioctl on the device node.
- Disconnect: Use 'syz_usb_disconnect(conn)'.
- Control Transfer: Use 'syz_usb_control_io(conn, req, res)'.
- Endpoint I/O: Use 'syz_usb_ep_write(conn, ep, len, data)' or 'syz_usb_ep_read(conn, ep, len, data)'
  (e.g. ep 0x81 IN / 0x02 OUT).
