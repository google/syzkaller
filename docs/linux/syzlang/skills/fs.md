---
name: fs
description: Filesystem Images, Mounts, Partition Tables and FUSE Emulation
---
# Filesystems, Mounts & FUSE
- Mount Image: Use 'syz_mount_image(fs, dir, flags, opts, chdir, size, img)'. Preferred method for mounting
  disk images (common types: 'ext4', 'btrfs', 'xfs', 'f2fs', 'erofs', 'fuse', 'vfat'). See 'filesystem.txt'
  for the complete list of supported filesystem definitions. If 'chdir' is 1, changes executor working directory
  into mount point 'dir'.
- FUSE Handling: Use 'syz_fuse_handle_req(fd, buf, len, res)' to emulate a FUSE daemon replying to kernel
  requests on '/dev/fuse' ('fd').
- Partition Tables: Use 'syz_read_part_table(size, img)' to parse GPT/MBR partition tables on loop devices.
