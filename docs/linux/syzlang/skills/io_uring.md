---
name: io_uring
description: High-Performance Ring I/O (io_uring) and Userspace Block Device (ublk) Emulation
---
# High-Performance Ring I/O (io_uring & ublk)
- io_uring Operations:
  * Use 'syz_io_uring_setup', 'syz_io_uring_submit', 'syz_io_uring_complete', and
    'syz_io_uring_modify_offsets' for asynchronous ring I/O operations.
- ublk Userspace Block Device Emulation:
  * Use 'syz_ublk_setup_io_uring', 'syz_ublk_add_dev', 'syz_ublk_setup_queues', and
    'syz_ublk_process_io' for userspace block device emulation.
