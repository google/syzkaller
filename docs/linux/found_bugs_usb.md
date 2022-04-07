# Found Linux kernel USB bugs

## Reported by syzbot

Starting from early 2019, bugs in the USB drivers are being automatically reported by the USB fuzzing instance of syzbot and can be found [here](https://syzkaller.appspot.com/upstream?manager=ci2-upstream-usb). A list of CVEs for some of those can be found here [here](https://www.openwall.com/lists/oss-security/2019/08/20/2).

Some of the USB bugs are reported by the KMSAN fuzzing instance and can be either found [here](https://groups.google.com/forum/#!searchin/syzkaller-bugs/%22kmsan%22$20%22usb%22%7Csort:date) or [here](https://syzkaller.appspot.com/upstream?manager=ci-upstream-kmsan-gce) (via a manual search, e.g. for `kernel-usb-infoleak`).

## Manually reported

These are the bugs that were manually reported before USB fuzzing was integrated into syzbot.

### USB drivers

* usb/core: memory corruption due to an out-of-bounds access in usb_destroy_configuration [[fix](https://www.spinics.net/lists/linux-usb/msg163644.html)] [CVE-2017-17558]
* [usb/net/zd1211rw: possible deadlock in zd_chip_disable_rxtx](https://groups.google.com/forum/#!topic/syzkaller/w_qXxIJfwmE)
* [usb/sound: use-after-free in __uac_clock_find_source](https://groups.google.com/forum/#!topic/syzkaller/FwYGmsC6c6E) [[fix](https://www.spinics.net/lists/alsa-devel/msg69833.html)]
* [usb/sound: slab-out-of-bounds in parse_audio_unit](https://groups.google.com/forum/#!topic/syzkaller/RJtoiisdruo) [[fix](https://www.spinics.net/lists/alsa-devel/msg69836.html)]
* [usb/media/em28xx: use-after-free in dvb_unregister_frontend](https://groups.google.com/forum/#!topic/syzkaller/wYG12peh1G4) [[fix](https://patchwork.linuxtv.org/patch/45219/)]
* [usb/media/technisat: slab-out-of-bounds in technisat_usb2_rc_query](https://groups.google.com/forum/#!topic/syzkaller/V-GvHOmJXO0)
* [usb/media/tm6000: use-after-free in tm6000_read_write_usb](https://groups.google.com/forum/#!topic/syzkaller/XLNeGPycipA)
* [usb/net/qmi_wwan: divide error in qmi_wwan_probe/usbnet_probe](https://groups.google.com/forum/#!topic/syzkaller/0e0gmaX9R0g) [[fix1](https://github.com/torvalds/linux/commit/2cb80187ba065d7decad7c6614e35e07aec8a974), [fix2](https://github.com/torvalds/linux/commit/7fd078337201cf7468f53c3d9ef81ff78cb6df3b)] [CVE-2017-16649, CVE-2017-16650]
* [usb/media/uvc: slab-out-of-bounds in uvc_probe](https://groups.google.com/forum/#!topic/syzkaller/Ot1fOE6v1d8)
* [usb/media/em28xx: use-after-free in em28xx_dvb_fini](https://groups.google.com/forum/#!topic/syzkaller/GcS_S4zY2ZQ)
* [usb/media/em28xx: use-after-free in v4l2_fh_init](https://groups.google.com/forum/#!topic/syzkaller/FnJq_QkwCLQ)
* [usb/media/pvrusb2: WARNING in pvr2_i2c_core_done/sysfs_remove_group](https://groups.google.com/forum/#!topic/syzkaller/0rKk1nKucQA)
* [usb/sound/usx2y: WARNING in usb_stream_start](https://groups.google.com/forum/#!topic/syzkaller/Gspr1ddXgHA) [[fix](https://github.com/torvalds/linux/commit/f9a1c372299fed53d4b72bb601f7f3bfe6f9999c)]
* [usb/net/hfa384x: WARNING in submit_rx_urb/usb_submit_urb](https://groups.google.com/forum/#!topic/syzkaller/hO1s_STq2II)
* [usb/media/dw2102: null-ptr-deref in dvb_usb_adapter_frontend_init/tt_s2_4600_frontend_attach](https://groups.google.com/forum/#!topic/syzkaller/kmNvrHHgVg4)
* [usb/net/asix: kernel hang in asix_phy_reset](https://groups.google.com/forum/#!topic/syzkaller/3yQVZuxIO-w)
* [usb/media/dtt200u: use-after-free in __dvb_frontend_free](https://groups.google.com/forum/#!topic/syzkaller/0HJQqTm0G_g) [[fix](https://github.com/torvalds/linux/commit/b1cb7372fa822af6c06c8045963571d13ad6348b)] [CVE-2017-16648]
* [usb/media/mxl111sf: trying to register non-static key in mxl111sf_ctrl_msg](https://groups.google.com/forum/#!topic/syzkaller/Xlvm_cnulFA)
* [usb/media/au0828: use-after-free in au0828_rc_unregister](https://groups.google.com/forum/#!topic/syzkaller/3yL32uggAT0)
* [usb/input/gtco: slab-out-of-bounds in parse_hid_report_descriptor](https://groups.google.com/forum/#!topic/syzkaller/McWFcOsA47Y) [[fix](https://github.com/torvalds/linux/commit/a50829479f58416a013a4ccca791336af3c584c7)] [CVE-2017-16643]
* [usb/core: slab-out-of-bounds in usb_get_bos_descriptor](https://groups.google.com/forum/#!topic/syzkaller/tzdz2fTB1K0) [[fix](https://github.com/torvalds/linux/commit/1c0edc3633b56000e18d82fc241e3995ca18a69e)] [CVE-2017-16535]
* [usb/net/asix: null-ptr-deref in asix_suspend](https://groups.google.com/forum/#!topic/syzkaller/_9a6pd-p_0E) [[fix](https://patchwork.ozlabs.org/patch/834686/)] [CVE-2017-16647]
* [usb/net/rt2x00: warning in rt2800_eeprom_word_index](https://groups.google.com/forum/#!topic/syzkaller/8vWPJ_maXQY)
* [usb/irda: global-out-of-bounds in irda_qos_bits_to_value](https://groups.google.com/forum/#!topic/syzkaller/PzxkGCumhwA)
* [usb/media/imon: global-out-of-bounds in imon_probe/imon_init_intf0](https://groups.google.com/forum/#!topic/syzkaller/o0LHaEe8Alg)
* [usb/sound: use-after-free in snd_usb_mixer_interrupt](https://groups.google.com/forum/#!topic/syzkaller/jf7GTr_g2CU) [[fix](https://github.com/torvalds/linux/commit/124751d5e63c823092060074bd0abaae61aaa9c4)] [CVE-2017-16527]
* [usb/net/rtlwifi: trying to register non-static key in rtl_c2hcmd_launcher](https://groups.google.com/forum/#!topic/syzkaller/vCTFZwPpmps)
* [usb/net/prism2usb: warning in hfa384x_usbctlxq_run/usb_submit_urb](https://groups.google.com/forum/#!topic/syzkaller/Bm5IO2dlcxA)
* [usb/nfs/pn533: use-after-free in pn533_send_complete](https://groups.google.com/forum/#!topic/syzkaller/-EkDbzlSuOY)
* [usb/media/imon: null-ptr-deref in imon_probe](https://groups.google.com/forum/#!topic/syzkaller/bBFN8imrjjo) [[fix](https://github.com/torvalds/linux/commit/58fd55e838276a0c13d1dc7c387f90f25063cbf3)] [CVE-2017-16537]
* [usb/net/prism2usb: warning in hfa384x_drvr_start/usb_submit_urb](https://groups.google.com/forum/#!topic/syzkaller/rPui1tYcrR0)
* [usb/net/ath6kl: GPF in ath6kl_usb_alloc_urb_from_pipe](https://groups.google.com/forum/#!topic/syzkaller/_ZE7_2A82Go)
* [usb/net/ar5523: warning in ar5523_submit_rx_cmd/usb_submit_urb](https://groups.google.com/forum/#!topic/syzkaller/5V7rYXYCuI4)
* [usb/media/uvc: BUG in uvc_mc_create_links/media_create_pad_link](https://groups.google.com/forum/#!topic/syzkaller/BOv81nh75TM)
* [usb/media/v4l2: use-after-free in video_unregister_device/device_del](https://groups.google.com/forum/#!topic/syzkaller/C2RyOxjhxh4)
* [usb/serial/visor: slab-out-of-bounds in palm_os_3_probe](https://groups.google.com/forum/#!topic/syzkaller/G5hNiJG2RXo) [[fix](https://groups.google.com/d/msg/syzkaller/G5hNiJG2RXo/Vu6_fuWJBAAJ) on the way]
* [usb/misc/usbtest: null-ptr-deref in usbtest_probe/get_endpoints](https://groups.google.com/forum/#!topic/syzkaller/l3870gs3LhA) [[fix](https://github.com/torvalds/linux/commit/7c80f9e4a588f1925b07134bb2e3689335f6c6d8)] [CVE-2017-16532]
* [usb/misc/ims-pcu: slab-out-of-bounds in ims_pcu_parse_cdc_data](https://groups.google.com/forum/#!topic/syzkaller/q6jjr1OhqO8) [[fix](https://github.com/torvalds/linux/commit/ea04efee7635c9120d015dcdeeeb6988130cb67a)] [CVE-2017-16645]
* [usb/serial: use-after-free in usb_serial_disconnect/__lock_acquire](https://groups.google.com/forum/#!topic/syzkaller/cMACrmo1x0k) [[fix1](https://github.com/torvalds/linux/commit/bd998c2e0df0469707503023d50d46cf0b10c787), [fix2](https://github.com/torvalds/linux/commit/299d7572e46f98534033a9e65973f13ad1ce9047)] [CVE-2017-16525]
* [usb/misc/rio500: double-free or invalid-free in disconnect_rio](https://groups.google.com/forum/#!topic/syzkaller/7JmbWaXqaIQ)
* [usb/sound/caiaq: warning in init_card/usb_submit_urb](https://groups.google.com/forum/#!topic/syzkaller/juLOtVudBkQ) [[fix](https://github.com/torvalds/linux/commit/58fc7f73a85d45a47057dad2af53502fdf6cf778)]
* [usb/input/aiptek: warning in aiptek_open/usb_submit_urb](https://groups.google.com/forum/#!topic/syzkaller/F7dVa-5YFlQ)
* [usb/net/lan78xx: use-after-free in lan78xx_write_reg](https://groups.google.com/forum/#!topic/syzkaller/5dEtqOKkv54)
* [usb/media/b2c2: GPF in flexcop_usb_transfer_init](https://groups.google.com/forum/#!topic/syzkaller/ToOkJ0Ox-HA)
* [usb/media/uvc: warning in uvc_scan_chain_forward/__list_add](https://groups.google.com/forum/#!topic/syzkaller/cEn3pmrYye4)
* [usb/sound/line6: trying to register non-static key in podhd_disconnect](https://groups.google.com/forum/#!topic/syzkaller/wEY6yXp-zC8)
* [usb/sound/line6: warning in line6_start_listen/usb_submit_urb](https://groups.google.com/forum/#!topic/syzkaller/33v4K1orrPk) [[fix](https://github.com/torvalds/linux/commit/2a4340c57717162c6bf07a0860d05711d4de994b)]
* [usb/media/lmedm04: GPF in lme2510_int_read/usb_pipe_endpoint](https://groups.google.com/forum/#!topic/syzkaller/XwNidsl4X04) [[fix1](https://patchwork.linuxtv.org/patch/44566/), [fix2](https://patchwork.linuxtv.org/patch/44567/)] [CVE-2017-16538]
* [usb/sound/bcd2000: warning in bcd2000_idrivers/usb/serial/usb-serial.cnit_device](https://groups.google.com/forum/#!topic/syzkaller/uU0anmKkD1w) [[fix](https://github.com/torvalds/linux/commit/6815a0b444572527256f0d0efd8efe3ddede6018)]
* [usb/wireless/rsi_91x: use-after-free write in __run_timers](https://groups.google.com/forum/#!topic/syzkaller/9IV2cQldrx0)
* [usb/media/zr364xx: GPF in zr364xx_vidioc_querycap/strlcpy](https://groups.google.com/forum/#!topic/syzkaller/-EuMlzvOHGo)
* [usb/media/stkwebcam: use-after-free in v4l2_ctrl_handler_free](https://groups.google.com/forum/#!topic/syzkaller/5kLo7aPtx1w)
* [usb/media/dib0700: BUG in stk7070p_frontend_attach/symbol_put_addr](https://groups.google.com/forum/#!topic/syzkaller/-d6ilzbVu_g) [[fix](https://patchwork.linuxtv.org/patch/45291/)] [CVE-2017-16646]
* [usb/sounds: slab-out-of-bounds read in snd_usb_create_streams](https://groups.google.com/forum/#!topic/syzkaller/rDzv5RP_f2M) [[fix](https://github.com/torvalds/linux/commit/bfc81a8bc18e3c4ba0cbaa7666ff76be2f998991)] [CVE-2017-16529]
* [usb/media/hdpvr: trying to register non-static key in hdpvr_probe](https://groups.google.com/forum/#!topic/syzkaller/ngC5SLvxPm4) [[fix](https://patchwork.kernel.org/patch/9966135/)] [CVE-2017-16644]
* [usb/net/hso: warning in hso_free_net_device](https://groups.google.com/forum/#!topic/syzkaller/J4Ua_T43Tjw)
* [usb/net/hso: global-out-of-bounds in hso_probe](https://groups.google.com/forum/#!topic/syzkaller/TDPcSXI2nBA)
* [usb/media/smsusb: use-after-free in worker_thread](https://groups.google.com/forum/#!topic/syzkaller/RS7QUTKo23s)
* [usb/storage/uas: slab-out-of-bounds in uas_probe](https://groups.google.com/forum/#!topic/syzkaller/pCswO77gRlM) [[fix](https://github.com/torvalds/linux/commit/786de92b3cb26012d3d0f00ee37adf14527f35c4)] [CVE-2017-16530]
* [usb/sound/usx2y: warning in usb_stream_new/__alloc_pages_slowpath](https://groups.google.com/forum/#!topic/syzkaller/vGwGJW_H-0I) [[fix](https://github.com/torvalds/linux/commit/7682e399485fe19622b6fd82510b1f4551e48a25)]
* [usb/media/pvrusb2: warning in pvr2_send_request_ex/usb_submit_urb](https://groups.google.com/forum/#!topic/syzkaller/M2GeMYS0f6E) [[fix](https://www.spinics.net/lists/kernel/msg2639143.html)]
* [usb/media/smsusb: null-ptr-deref in smsusb_init_device](https://groups.google.com/forum/#!topic/syzkaller/yvhFawNoqxE)
* [usb/media/cx231xx: null-ptr-deref in cx231xx_usb_probe](https://groups.google.com/forum/#!topic/syzkaller/WlUAVfDvpRk) [[fix](https://patchwork.kernel.org/patch/9963527/)] [CVE-2017-16536]
* [usb/net/p54: trying to register non-static key in p54_unregister_leds](https://groups.google.com/forum/#!topic/syzkaller/H6mX3aQPvvQ) [[fix](https://patchwork.kernel.org/patch/9972281/)]
* [usb/core: slab-out-of-bounds read in cdc_parse_cdc_header](https://groups.google.com/forum/#!topic/syzkaller/nXnjqI73uPo) [[fix](https://github.com/torvalds/linux/commit/2e1c42391ff2556387b3cb6308b24f6f65619feb)] [CVE-2017-16534]
* [usb/hid: slab-out-of-bounds read in usbhid_parse](https://groups.google.com/forum/#!topic/syzkaller/CxkJ9QZgwlM) [[fix](https://github.com/torvalds/linux/commit/f043bfc98c193c284e2cd768fefabe18ac2fed9b)] [CVE-2017-16533]
* [usb/core: slab-out-of-bounds in usb_set_configuration](https://groups.google.com/forum/#!topic/syzkaller/hP6L-m59m_8) [[fix](https://github.com/torvalds/linux/commit/bd7a3fe770ebd8391d1c7d072ff88e9e76d063eb)] [CVE-2017-16531]
* [usb/uwb: WARNING in hwarc_neep_init/usb_submit_urb](https://groups.google.com/forum/#!topic/syzkaller/kxql4awIiR4) [[fix](https://github.com/torvalds/linux/commit/70e743e4cec3733dc13559f6184b35d358b9ef3f)]
* [usb/uwb: GPF in uwbd_start](https://groups.google.com/forum/#!topic/syzkaller/zROBxKXzHDk) [[fix](https://github.com/torvalds/linux/commit/bbf26183b7a6236ba602f4d6a2f7cade35bba043)] [CVE-2017-16526]
* [usb/joystick: warnings in xpad_start_input and xpad_try_sending_next_out_packet](https://groups.google.com/forum/#!topic/syzkaller/nMIkggZOUxA) [[fix](https://github.com/torvalds/linux/commit/122d6a347329818419b032c5a1776e6b3866d9b9)]
* [usb/midi: use-after-free in snd_rawmidi_dev_seq_free](https://groups.google.com/forum/#!topic/syzkaller/kuZzDHGkQu8) [[fix](https://github.com/torvalds/linux/commit/fc27fe7e8deef2f37cba3f2be2d52b6ca5eb9d57)] [CVE-2017-16528]
* [usb/core: warning in usb_create_ep_devs/sysfs_create_dir_ns](https://groups.google.com/forum/#!topic/syzkaller/wvB_W78nTh0) [[fix](https://github.com/torvalds/linux/commit/0a8fd1346254974c3a852338508e4a4cddbb35f1)]

### GadgetFS

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
