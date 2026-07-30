---
name: wifi
description: 802.11 Wi-Fi, Wireless Networking and Netlink Injection Rules
---
# Network & Wireless (802.11 Wi-Fi, Netlink)
- 802.11 Wi-Fi Injection: Use 'syz_80211_inject_frame(mac, frame, len)' to send 802.11 management/data frames
  to mac80211_hwsim. Always insert nanosleep delays between successive auth, assoc, and probe response frames.
- 802.11 Ad-Hoc: Use 'syz_80211_join_ibss(ifname, ssid, len, freq)' to join IBSS networks.
- Generic Netlink Family ID: Use 'syz_genetlink_get_family_id(name, fd)' to look up Netlink IDs
  (e.g. for 'nl80211', 'wireguard', 'team').
- TCP State Tracking: Use 'syz_extract_tcp_res(res, seq_inc, ack_inc)' to extract TCP sequence/ACK numbers.
- Packet Injection: Use 'syz_emit_ethernet(len, packet, frags)' to inject raw L2 frames into
  the executor TUN/TAP interface.
