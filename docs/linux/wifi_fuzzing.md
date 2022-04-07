# Wifi fuzzing

Syzkaller supports fuzzing Linux's 802.11 (WiFi) subsystem.
Currently it focuses on the following two targets.
- Configuration and management functionality. It is exposed via the nl80211 interface of the Linux kernel.
- Incoming wireless frames processing. Syzkaller reaches the corresponding code by injecting 802.11 frames. This functionality is under development at the moment.

This document describes the internals of the approach and keeps track of the progress towards its complete implementation.

## General approach

Syzkaller uses [mac80211_hwsim](https://wireless.wiki.kernel.org/en/users/drivers/mac80211_hwsim) module to emulate wifi devices.

In order to simplify reproducer generation and to have an operable 802.11 network from the very beginning, syzkaller performs the following at executor initialization. If `wifi` feature is enabled (it is enabled by default), then:
1. Two virtual wifi devices are created and assigned predefined MAC addresses (08:02:11:00:00:00 and 08:02:11:00:00:01).
2. These devices are put into `IBSS` mode.
3. These devices form an IBSS network. Network parameters are predefined: BSSID (50:50:50:50:50:50), SSID('\x10\x10\x10\x10\x10\x10'), channel (2412 MHz). After this step, the network is operable and 802.11 frame injection is possible.

These steps happen inside the `initialize_wifi_devices` function of `executor/common_linux.h`.

In order to facilitate 802.11 fuzzing, two pseudo syscalls are also introduced.
1. `syz_80211_inject_frame(mac_addr, buf, buf_len)` performs 802.11 frame injection. The frame will appear to be received at the specified network interface.
2. `syz_80211_join_ibss(network_interface, ssid, ssid_len, wait_mode)` puts the corresponding network interface into IBSS mode and joins the specified ad-hoc network. Although an IBSS network is already formed at the very beginning, the fuzzer can quickly take interfaces out of operational state (e.g. by deleting and re-adding it), and it will be very problematic for the fuzzer to restore the operational state. Similar syscalls might be added for other wifi modes as well.

## nl80211 commands list

| Command | In descriptions | Comment |
| ------- | --------------- | ------- |
| `NL80211_CMD_ABORT_SCAN` | yes | |
| `NL80211_CMD_ADD_NAN_FUNCTION` | yes | Not supported by `mac80211_hwsim` |
| `NL80211_CMD_ADD_TX_TS` | yes | |
| `NL80211_CMD_ASSOCIATE` | yes | |
| `NL80211_CMD_AUTHENTICATE` | yes | |
| `NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL` | yes | |
| `NL80211_CMD_CHANGE_NAN_CONFIG` | yes | Not supported by `mac80211_hwsim` |
| `NL80211_CMD_CHANNEL_SWITCH` | yes | |
| `NL80211_CMD_CONNECT` | yes | |
| `NL80211_CMD_CONTROL_PORT_FRAME` | yes | |
| `NL80211_CMD_CRIT_PROTOCOL_START` | yes | |
| `NL80211_CMD_CRIT_PROTOCOL_STOP` | yes | |
| `NL80211_CMD_DEAUTHENTICATE` | yes | |
| `NL80211_CMD_DEL_INTERFACE` | yes | |
| `NL80211_CMD_DEL_KEY` | yes | |
| `NL80211_CMD_DEL_MPATH` | yes | |
| `NL80211_CMD_DEL_NAN_FUNCTION` | yes | Not supported by `mac80211_hwsim` |
| `NL80211_CMD_DEL_PMK` | yes | |
| `NL80211_CMD_DEL_PMKSA` | yes | |
| `NL80211_CMD_DEL_STATION` | yes | |
| `NL80211_CMD_DEL_TX_TS` | yes | |
| `NL80211_CMD_DISASSOCIATE` | yes | |
| `NL80211_CMD_DISCONNECT` | yes | |
| `NL80211_CMD_EXTERNAL_AUTH` | yes | |
| `NL80211_CMD_FLUSH_PMKSA` | yes | |
| `NL80211_CMD_FRAME` | yes | |
| `NL80211_CMD_FRAME_WAIT_CANCEL` | yes | |
| `NL80211_CMD_GET_COALESCE` | yes | |
| `NL80211_CMD_GET_FTM_RESPONDER_STATS` | yes | |
| `NL80211_CMD_GET_INTERFACE` | yes | |
| `NL80211_CMD_GET_KEY` | yes | |
| `NL80211_CMD_GET_MESH_CONFIG` | yes | |
| `NL80211_CMD_GET_MPATH` | yes | |
| `NL80211_CMD_GET_MPP` | yes | |
| `NL80211_CMD_GET_POWER_SAVE` | yes | |
| `NL80211_CMD_GET_PROTOCOL_FEATURES` | yes | |
| `NL80211_CMD_GET_REG` | yes | |
| `NL80211_CMD_GET_SCAN` | yes | |
| `NL80211_CMD_GET_STATION` | yes | |
| `NL80211_CMD_GET_SURVEY` | yes | |
| `NL80211_CMD_GET_WIPHY` | yes | |
| `NL80211_CMD_GET_WOWLAN` | yes | Requires `CONFIG_PM` |
| `NL80211_CMD_JOIN_IBSS` | yes | |
| `NL80211_CMD_JOIN_MESH` | yes | |
| `NL80211_CMD_JOIN_OCB` | yes | |
| `NL80211_CMD_LEAVE_IBSS` | yes | |
| `NL80211_CMD_LEAVE_MESH` | yes | |
| `NL80211_CMD_LEAVE_OCB` | yes | |
| `NL80211_CMD_NEW_INTERFACE` | yes | |
| `NL80211_CMD_NEW_KEY` | yes | |
| `NL80211_CMD_NEW_MPATH` | yes | |
| `NL80211_CMD_NEW_STATION` | yes | |
| `NL80211_CMD_NOTIFY_RADAR` | yes | |
| `NL80211_CMD_PEER_MEASUREMENT_START` | yes | |
| `NL80211_CMD_PROBE_CLIENT` | yes | |
| `NL80211_CMD_PROBE_MESH_LINK` | yes | |
| `NL80211_CMD_RADAR_DETECT` | yes | |
| `NL80211_CMD_REGISTER_BEACONS` | yes | |
| `NL80211_CMD_REGISTER_FRAME` | yes | |
| `NL80211_CMD_RELOAD_REGDB` | yes | |
| `NL80211_CMD_REMAIN_ON_CHANNEL` | yes | |
| `NL80211_CMD_REQ_SET_REG` | yes | |
| `NL80211_CMD_SET_BEACON` | yes | |
| `NL80211_CMD_SET_BSS` | yes | |
| `NL80211_CMD_SET_CHANNEL` | yes | |
| `NL80211_CMD_SET_COALESCE` | yes | |
| `NL80211_CMD_SET_CQM` | yes | |
| `NL80211_CMD_SET_INTERFACE` | yes | |
| `NL80211_CMD_SET_KEY` | yes | |
| `NL80211_CMD_SET_MAC_ACL` | yes | |
| `NL80211_CMD_SET_MCAST_RATE` | yes | |
| `NL80211_CMD_SET_MESH_CONFIG` | yes | |
| `NL80211_CMD_SET_MPATH` | yes | |
| `NL80211_CMD_SET_MULTICAST_TO_UNICAST` | yes | |
| `NL80211_CMD_SET_NOACK_MAP` | yes | |
| `NL80211_CMD_SET_PMK` | yes | |
| `NL80211_CMD_SET_PMKSA` | yes | |
| `NL80211_CMD_SET_POWER_SAVE` | yes | |
| `NL80211_CMD_SET_QOS_MAP` | yes | |
| `NL80211_CMD_SET_REG` | yes | Requires `CONFIG_CFG80211_CRDA_SUPPORT`|
| `NL80211_CMD_SET_REKEY_OFFLOAD` | yes | |
| `NL80211_CMD_SET_STATION` | yes | |
| `NL80211_CMD_SET_TID_CONFIG` | yes | |
| `NL80211_CMD_SET_TX_BITRATE_MASK` | yes | |
| `NL80211_CMD_SET_WDS_PEER` | yes | |
| `NL80211_CMD_SET_WIPHY` | yes | |
| `NL80211_CMD_SET_WIPHY_NETNS` | yes | |
| `NL80211_CMD_SET_WOWLAN` | yes | Requires `CONFIG_PM` |
| `NL80211_CMD_START_AP` | yes | |
| `NL80211_CMD_START_NAN` | yes | Not supported by `mac80211_hwsim` |
| `NL80211_CMD_START_P2P_DEVICE` | yes | |
| `NL80211_CMD_START_SCHED_SCAN` | yes | |
| `NL80211_CMD_STOP_AP` | yes | |
| `NL80211_CMD_STOP_NAN` | yes | Not supported by `mac80211_hwsim` |
| `NL80211_CMD_STOP_P2P_DEVICE` | yes | |
| `NL80211_CMD_STOP_SCHED_SCAN` | yes | |
| `NL80211_CMD_TDLS_CANCEL_CHANNEL_SWITCH` | yes | |
| `NL80211_CMD_TDLS_CHANNEL_SWITCH` | yes | |
| `NL80211_CMD_TDLS_MGMT` | yes | |
| `NL80211_CMD_TDLS_OPER` | yes | |
| `NL80211_CMD_TESTMODE` | yes | Requires `CONFIG_NL80211_TESTMODE` |
| `NL80211_CMD_TRIGGER_SCAN` | yes | |
| `NL80211_CMD_UNEXPECTED_FRAME` | yes | |
| `NL80211_CMD_UPDATE_CONNECT_PARAMS` | yes | |
| `NL80211_CMD_UPDATE_FT_IES` | yes | |
| `NL80211_CMD_UPDATE_OWE_INFO` | yes | |
| `NL80211_CMD_VENDOR` | yes | |

## 802.11 frames
This is not an exhaustive list as it does not include all frames/commands that are defined by 802.11 standards. However, it aims to include all frames supported by mac80211.

### Data frames

| Feature | In descriptions | Supported by mac80211 |
| ------- | --------------- | --------------------- |
| QoS control | yes | yes |
| HT control | yes | yes |
| A-MSDU | yes | yes |
| Short A-MSDU | no | no? |
| Frame encryption | no | yes |

### Management frames
| Command | In descriptions | Supported by mac80211 |
| ------- | --------------- | --------------------- |
| Association Request | yes | yes |
| Association Response | yes | yes |
| Reassociation Request | yes | yes |
| Reassociation Response | yes | yes |
| Probe Request | yes | yes |
| Probe Response | yes | yes |
| Timing Advertisement | not yes | no |
| Beacon | yes | yes |
| ATIM | not yes | no |
| Disassociation | yes | yes |
| Authentication |  yes | yes |
| Deauthentication | yes | yes |
| Action | see below | yes |
| Action No Ack | see below | no |

### Management Actions
| Category | Command | In descriptions | Supported by mac80211 |
| -------- | ------- | --------------- | --------------------- |
| Spectrum Management | Measurement Request | partially | receives and refuses |
| Spectrum Management | Measurement Report | no | no |
| Spectrum Management | TPC Request | no  | no |
| Spectrum Management | TPC Report | no | no |
| Spectrum Management | Channel Switch Announcement | yes | yes |
| Block ACK | ADDBA Request | yes | yes |
| Block ACK | ADDBA Response | yes | yes |
| Block ACK | DELBA | yes | yes |
| Public | Extended Channel Switch Announcement | yes | yes |
| HT | Notify Channel Width | yes | yes |
| HT | SM Power Save | yes | yes |
| HT | PMSP | no | no |
| HT | Set PCO Phase | no | no |
| HT | CSI | no | no |
| SA Query | SA Query Request | yes | yes |
| SA Query | SA Query Response | no | no |
| TLDS | Setup Request | yes | yes |
| TLDS | Setup Response | yes | yes |
| TLDS | Setup Confirm | yes | yes |
| TLDS | Teardown | yes | yes |
| TLDS | Discover Request | yes | yes |
| TLDS | Channel Switch Request | yes | yes |
| TLDS | Channel Switch Response | yes | yes |
| Mesh | HWMP Mesh Path Selection | yes | yes |
| Self Protected | Mesh Peering Open | yes | yes |
| Self Protected | Mesh Peering Close | yes | yes |
| Self Protected | Mesh Peering Confirm | yes | yes |
| VHT | Operating Mode Notification | yes | yes |
| VHT | Group ID Management | yes | yes |

### Control frames
| Command | In descriptions | Supported by mac80211 |
| ------- | --------------- | --------------------- |
| Trigger | no | no |
| Beamforming Report Poll | no | no |
| VHT/HE NDP Announcement | no | no |
| Control Frame Extension | no | no |
| Control Wrapper | no | no |
| Block Ack Request (BAR) | yes (802.11n) | yes |
| Block Ack (BA) | yes (802.11n) | ? |
| PS-Poll | yes | ? |
| RTS | yes | no |
| CTS | yes | no |
| ACK | yes | no |
| CF-End | yes | ? |
| CF-End + CF-ACK | yes | ? |

### Information Elements

| ID | IE | In descriptions | Supported by mac80211 |
| -- | -- | ----- | --------------------- |
| 0 | SSID | yes | yes |
| 1 | Supported Rates | yes | yes |
| 3 | DS | yes | yes |
| 4 | CF | yes | yes |
| 5 | Traffic Indication Map | yes | yes |
| 6 | IBSS | yes | yes |
| 7 | HT Capabilities | yes | ? |
| 10 | Request | no | no |
| 37 | Channel Switch Announcement | yes | yes |
| 38 | Measurement Request | yes | yes |
| 42 | Extended Rate PHY (ERP) | yes | yes? |
| 55 | Fast BSS Transition element | yes | yes |
| 60 | Extended Channel Switch Announcement | yes | ? |
| 62 | Secondary Channel Offset | yes | yes |
| 101 | Link Identifier | yes | ? |
| 104 | Channel Switch Timing Information | yes | ? |
| 113 | Mesh Config | yes | yes |
| 114 | Mesh ID | yes | yes |
| 117 | Mesh Peering Management | yes | yes |
| 118 | MESH Channel Switch | yes | yes |
| 126 | RANN | yes | yes |
| 130 | PREQ | yes | yes |
| 131 | PREP | yes | yes |
| 132 | PERR | yes | yes |
| 140 | MIC | yes | yes |
| 189 | GCR Group Address | yes | no |
