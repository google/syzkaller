# Found Linux kernel USB bugs

## USB drivers

* [usb/net/asix: null-ptr-deref in asix_suspend](https://groups.google.com/forum/#!topic/syzkaller/_9a6pd-p_0E)
* [usb/net/rt2x00: warning in rt2800_eeprom_word_index](https://groups.google.com/forum/#!topic/syzkaller/8vWPJ_maXQY)
* [usb/irda: global-out-of-bounds in irda_qos_bits_to_value](https://groups.google.com/forum/#!topic/syzkaller/PzxkGCumhwA)
* [usb/media/imon: global-out-of-bounds in imon_probe/imon_init_intf0](https://groups.google.com/forum/#!topic/syzkaller/o0LHaEe8Alg)
* [usb/sound: use-after-free in snd_usb_mixer_interrupt](https://groups.google.com/forum/#!topic/syzkaller/jf7GTr_g2CU) [[fix](https://groups.google.com/d/msg/syzkaller/jf7GTr_g2CU/WixfevMwCQAJ)]
* [usb/net/rtlwifi: trying to register non-static key in rtl_c2hcmd_launcher](https://groups.google.com/forum/#!topic/syzkaller/vCTFZwPpmps)
* [usb/net/prism2usb: warning in hfa384x_usbctlxq_run/usb_submit_urb](https://groups.google.com/forum/#!topic/syzkaller/Bm5IO2dlcxA)
* [usb/nfs/pn533: use-after-free in pn533_send_complete](https://groups.google.com/forum/#!topic/syzkaller/-EkDbzlSuOY)
* [usb/media/imon: null-ptr-deref in imon_probe](https://groups.google.com/forum/#!topic/syzkaller/bBFN8imrjjo) [[fix](https://patchwork.kernel.org/patch/9994017/)]
* [usb/net/prism2usb: warning in hfa384x_drvr_start/usb_submit_urb](https://groups.google.com/forum/#!topic/syzkaller/rPui1tYcrR0)
* [usb/net/ath6kl: GPF in ath6kl_usb_alloc_urb_from_pipe](https://groups.google.com/forum/#!topic/syzkaller/_ZE7_2A82Go)
* [usb/net/ar5523: warning in ar5523_submit_rx_cmd/usb_submit_urb](https://groups.google.com/forum/#!topic/syzkaller/5V7rYXYCuI4)
* [usb/media/uvc: BUG in uvc_mc_create_links/media_create_pad_link](https://groups.google.com/forum/#!topic/syzkaller/BOv81nh75TM)
* [usb/media/v4l2: use-after-free in video_unregister_device/device_del](https://groups.google.com/forum/#!topic/syzkaller/C2RyOxjhxh4)
* [usb/serial/visor: slab-out-of-bounds in palm_os_3_probe](https://groups.google.com/forum/#!topic/syzkaller/G5hNiJG2RXo) [fix on the way]
* [usb/misc/usbtest: null-ptr-deref in usbtest_probe/get_endpoints](https://groups.google.com/forum/#!topic/syzkaller/l3870gs3LhA) [[fix](https://www.spinics.net/lists/linux-usb/msg161144.html)]
* [usb/misc/ims-pcu: slab-out-of-bounds in ims_pcu_parse_cdc_data](https://groups.google.com/forum/#!topic/syzkaller/q6jjr1OhqO8) [[fix](https://groups.google.com/d/msg/syzkaller/q6jjr1OhqO8/eN75-uyGCAAJ)]
* [usb/serial: use-after-free in usb_serial_disconnect/__lock_acquire](https://groups.google.com/forum/#!topic/syzkaller/cMACrmo1x0k) [[fix1](https://www.spinics.net/lists/linux-usb/msg161255.html), [fix2](https://www.spinics.net/lists/linux-usb/msg161253.html)]
* [usb/misc/rio500: double-free or invalid-free in disconnect_rio](https://groups.google.com/forum/#!topic/syzkaller/7JmbWaXqaIQ)
* [usb/sound/caiaq: warning in init_card/usb_submit_urb](https://groups.google.com/forum/#!topic/syzkaller/juLOtVudBkQ) [[fix](https://www.spinics.net/lists/linux-usb/msg161460.html)]
* [usb/input/aiptek: warning in aiptek_open/usb_submit_urb](https://groups.google.com/forum/#!topic/syzkaller/F7dVa-5YFlQ)
* [usb/net/lan78xx: use-after-free in lan78xx_write_reg](https://groups.google.com/forum/#!topic/syzkaller/5dEtqOKkv54)
* [usb/media/b2c2: GPF in flexcop_usb_transfer_init](https://groups.google.com/forum/#!topic/syzkaller/ToOkJ0Ox-HA)
* [usb/media/uvc: warning in uvc_scan_chain_forward/__list_add](https://groups.google.com/forum/#!topic/syzkaller/cEn3pmrYye4)
* [usb/sound/line6: trying to register non-static key in podhd_disconnect](https://groups.google.com/forum/#!topic/syzkaller/wEY6yXp-zC8)
* [usb/sound/line6: warning in line6_start_listen/usb_submit_urb](https://groups.google.com/forum/#!topic/syzkaller/33v4K1orrPk) [[fix](https://www.spinics.net/lists/linux-usb/msg161459.html)]
* [usb/media/lmedm04: GPF in lme2510_int_read/usb_pipe_endpoint](https://groups.google.com/forum/#!topic/syzkaller/XwNidsl4X04) [[fix1](https://patchwork.linuxtv.org/patch/44566/), [fix2](https://patchwork.linuxtv.org/patch/44567/)]
* [usb/sound/bcd2000: warning in bcd2000_idrivers/usb/serial/usb-serial.cnit_device](https://groups.google.com/forum/#!topic/syzkaller/uU0anmKkD1w) [[fix](https://www.spinics.net/lists/linux-usb/msg161457.html)]
* [usb/wireless/rsi_91x: use-after-free write in __run_timers](https://groups.google.com/forum/#!topic/syzkaller/9IV2cQldrx0)
* [usb/media/zr364xx: GPF in zr364xx_vidioc_querycap/strlcpy](https://groups.google.com/forum/#!topic/syzkaller/-EuMlzvOHGo)
* [usb/media/stkwebcam: use-after-free in v4l2_ctrl_handler_free](https://groups.google.com/forum/#!topic/syzkaller/5kLo7aPtx1w)
* [usb/media/dib0700: BUG in stk7070p_frontend_attach/symbol_put_addr](https://groups.google.com/forum/#!topic/syzkaller/-d6ilzbVu_g)
* [usb/sounds: slab-out-of-bounds read in snd_usb_create_streams](https://groups.google.com/forum/#!topic/syzkaller/rDzv5RP_f2M) [[fix](https://github.com/torvalds/linux/commit/bfc81a8bc18e3c4ba0cbaa7666ff76be2f998991)]
* [usb/media/hdpvr: trying to register non-static key in hdpvr_probe](https://groups.google.com/forum/#!topic/syzkaller/ngC5SLvxPm4) [[fix](https://patchwork.kernel.org/patch/9966135/)]
* [usb/net/hso: warning in hso_free_net_device](https://groups.google.com/forum/#!topic/syzkaller/J4Ua_T43Tjw)
* [usb/net/hso: global-out-of-bounds in hso_probe](https://groups.google.com/forum/#!topic/syzkaller/TDPcSXI2nBA)
* [usb/media/smsusb: use-after-free in worker_thread](https://groups.google.com/forum/#!topic/syzkaller/RS7QUTKo23s)
* [usb/storage/uas: slab-out-of-bounds in uas_probe](https://groups.google.com/forum/#!topic/syzkaller/pCswO77gRlM) [[fix](786de92b3cb26012d3d0f00ee37adf14527f35c4)]
* [usb/sound/usx2y: warning in usb_stream_new/__alloc_pages_slowpath](https://groups.google.com/forum/#!topic/syzkaller/vGwGJW_H-0I) [[fix](https://github.com/torvalds/linux/commit/7682e399485fe19622b6fd82510b1f4551e48a25)]
* [usb/media/pvrusb2: warning in pvr2_send_request_ex/usb_submit_urb](https://groups.google.com/forum/#!topic/syzkaller/M2GeMYS0f6E)
* [usb/media/smsusb: null-ptr-deref in smsusb_init_device](https://groups.google.com/forum/#!topic/syzkaller/yvhFawNoqxE)
* [usb/media/cx231xx: null-ptr-deref in cx231xx_usb_probe](https://groups.google.com/forum/#!topic/syzkaller/WlUAVfDvpRk) [[fix](https://patchwork.kernel.org/patch/9963527/)]
* [usb/net/p54: trying to register non-static key in p54_unregister_leds](https://groups.google.com/forum/#!topic/syzkaller/H6mX3aQPvvQ) [[fix](https://patchwork.kernel.org/patch/9972281/)]
* [usb/core: slab-out-of-bounds read in cdc_parse_cdc_header](https://groups.google.com/forum/#!topic/syzkaller/nXnjqI73uPo) [[fix](https://github.com/torvalds/linux/commit/2e1c42391ff2556387b3cb6308b24f6f65619feb)]
* [usb/hid: slab-out-of-bounds read in usbhid_parse](https://groups.google.com/forum/#!topic/syzkaller/CxkJ9QZgwlM) [[fix](https://patchwork.kernel.org/patch/9975711/)]
* [usb/core: slab-out-of-bounds in usb_set_configuration](https://groups.google.com/forum/#!topic/syzkaller/hP6L-m59m_8) [[fix](https://github.com/torvalds/linux/commit/bd7a3fe770ebd8391d1c7d072ff88e9e76d063eb)]
* [usb/uwb: WARNING in hwarc_neep_init/usb_submit_urb](https://groups.google.com/forum/#!topic/syzkaller/kxql4awIiR4) [[fix](https://github.com/torvalds/linux/commit/70e743e4cec3733dc13559f6184b35d358b9ef3f)]
* [usb/uwb: GPF in uwbd_start](https://groups.google.com/forum/#!topic/syzkaller/zROBxKXzHDk) [[fix](https://github.com/torvalds/linux/commit/bbf26183b7a6236ba602f4d6a2f7cade35bba043)]
* [usb/joystick: warnings in xpad_start_input and xpad_try_sending_next_out_packet](https://groups.google.com/forum/#!topic/syzkaller/nMIkggZOUxA) [[fix](https://github.com/torvalds/linux/commit/122d6a347329818419b032c5a1776e6b3866d9b9)]
* [usb/midi: use-after-free in snd_rawmidi_dev_seq_free](https://groups.google.com/forum/#!topic/syzkaller/kuZzDHGkQu8) [[fix](https://github.com/torvalds/linux/commit/fc27fe7e8deef2f37cba3f2be2d52b6ca5eb9d57)]
* [usb/core: warning in usb_create_ep_devs/sysfs_create_dir_ns](https://groups.google.com/forum/#!topic/syzkaller/wvB_W78nTh0) [[fix](https://github.com/torvalds/linux/commit/0a8fd1346254974c3a852338508e4a4cddbb35f1)]

## GadgetFS

* [usb/gadget: stalls in dummy_timer / usbtouch_probe](https://groups.google.com/forum/#!topic/syzkaller/9MKj0sRWn3Y) [[fix](https://github.com/torvalds/linux/commit/0173a68bfb0ad1c72a6ee39cc485aa2c97540b98)]
* [usb/gadget: null-ptr-deref in dev_ioctl](https://groups.google.com/forum/#!topic/syzkaller/ShlQyQLCe60) [[fix](https://github.com/torvalds/linux/commit/520b72fc64debf8a86c3853b8e486aa5982188f0)]
* [usb/gadget: copy_to_user called with spinlock held](https://groups.google.com/forum/#!topic/syzkaller/xmFE5DTHkME) [[fix](https://github.com/torvalds/linux/commit/6e76c01e71551cb221c1f3deacb9dcd9a7346784)]
* [usb/gadget: potential deadlock in gadgetfs_suspend](https://groups.google.com/forum/#!topic/syzkaller/J_It9ipKXhk) [[fix](https://github.com/torvalds/linux/commit/f16443a034c7aa359ddf6f0f9bc40d01ca31faea)]
* [usb/gadget: another GPF in usb_gadget_unregister_driver](https://groups.google.com/forum/#!topic/syzkaller/I6t-ToS5cxE) [[fix](https://github.com/torvalds/linux/commit/f50b878fed33e360d01dcdc31a8eeb1815d033d5)]
* [usb/gadget: warning in ep_write_iter/__alloc_pages_nodemask](https://groups.google.com/forum/#!topic/syzkaller/d2FD55alPqY) [[fix](https://github.com/torvalds/linux/commit/bb1107f7c6052c863692a41f78c000db792334bf)]
* [usb/gadget: slab-out-of-bounds write in dev_config](https://groups.google.com/forum/#!topic/syzkaller/Y4hEomcJgjY) [[fix](https://github.com/torvalds/linux/commit/faab50984fe6636e616c7cc3d30308ba391d36fd)]
* [usb/gadget: warning in dummy_free_request](https://groups.google.com/forum/#!topic/syzkaller/nNVKOT0fdaY) [[fix](https://github.com/torvalds/linux/commit/bcdbeb844773333d2d1c08004f3b3e25921040e5)]
* [usb/gadget: poor checks of wTotalLength in config descriptors](https://groups.google.com/forum/#!topic/syzkaller/PBWoEbmzrto) [[fix](https://github.com/torvalds/linux/commit/1c069b057dcf64fada952eaa868d35f02bb0cfc2)]
* [usb/gadget: use-after-free in gadgetfs_setup](https://groups.google.com/forum/#!topic/syzkaller/PBWoEbmzrto) [[fix](https://github.com/torvalds/linux/commit/add333a81a16abbd4f106266a2553677a165725f)]
* [usb/gadget: GPF in usb_gadget_unregister_driver](https://groups.google.com/forum/#!topic/syzkaller/HDawLBeeORI) [[fix](https://github.com/torvalds/linux/commit/7b01738112608ce47083178ae2b9ebadf02d32cc)]
* [usb/gadget: warning in dev_config/memdup_user](https://groups.google.com/forum/#!topic/syzkaller/bt6m57DyKLk) [[fix](https://github.com/torvalds/linux/commit/0994b0a257557e18ee8f0b7c5f0f73fe2b54eec1)]
