# Setup: Linux host, Intel Simics vm, x86-64 kernel

These are the instructions on how to fuzz a custom built x86-64 Linux kernel that runs on an
[Intel Simics](https://www.intel.com/content/www/us/en/developer/articles/tool/simics-simulator.html)
virtual platform. This is useful for platforms whose devices are only available in the simulator,
so that the kernel and drivers can be fuzzed long before, or without, real hardware. The
instructions use the public Quick-Start Platform (QSP) x86 target.

The `simics` VM type starts one simulator process per VM in a Simics project, reads the kernel
console from the simulated serial port through a telnet port and runs commands over ssh through
a port that the simulated network's service node forwards to guest port 22.

## Simics

Install Simics with the Intel Simics Package Manager (`ispm`) and create a project with the QSP x86
packages:

```
ispm packages --install-bundle simics-7-packages-<version>-linux64.ispm \
    --install-dir ~/simics/install --non-interactive
~/simics/install/simics-7.<version>/bin/project-setup ~/simics/project
```

List the installed packages that the project should use (base, QSP x86, QSP CPU) in
`~/simics/project/.package-list`, one installation path per line, and update the project with
`project-setup --package-list .package-list .` in the project directory. Check that the target
is available:

```
cd ~/simics/project
./simics --list-targets | grep qsp-x86/user-provided-linux
```

Simics uses VMP (hardware-assisted x86 simulation) automatically when the host has Intel VT-x and
the `vmxmon` kernel module is loaded (`sudo ~/simics/project/bin/vmp-kernel-install`); otherwise
it prints `VMP disabled` and falls back to software simulation, which also works, only slower.

## Kernel

Build the kernel with the [usual syzkaller options](kernel_configs.md): at least `CONFIG_KCOV`,
`CONFIG_KASAN`, `CONFIG_DEBUG_INFO`, `CONFIG_DEBUG_FS` and `CONFIG_KALLSYMS`. The default target
boots the `bzImage` directly, without an initramfs, and the image has no modules for it, so build
in (`=y`, not `=m`):

- `CONFIG_VIRTIO_PCI`, `CONFIG_VIRTIO_BLK` and the root filesystem (e.g. `CONFIG_EXT4_FS`):
  the image is attached as a virtio block device;
- `CONFIG_E1000E`: the QSP x86 network adapter;
- `CONFIG_BINFMT_MISC`: otherwise systemd's automount of `/proc/sys/fs/binfmt_misc` in the guest
  makes the executor fail with `SYZFAIL: mount(binfmt_misc) failed`;
- everything else the fuzzer should reach, e.g. `CONFIG_TUN` for network packet injection.

For example, starting from a distribution `.config`:

```
scripts/config --file $BUILD/.config -e VIRTIO_PCI -e VIRTIO_BLK -e EXT4_FS -e JBD2 \
    -e VFAT_FS -e NLS_CODEPAGE_437 -e NLS_ASCII -e E1000E -e PTP_1588_CLOCK \
    -e BINFMT_MISC -e TUN -e VETH -e AUTOFS_FS -e KCOV -e KCOV_ENABLE_COMPARISONS -e KASAN
make O=$BUILD olddefconfig
make O=$BUILD -j$(nproc) bzImage
```

(`VFAT_FS`/`NLS_*`: the EFI system partition is mounted from `/etc/fstab`, a failing mount drops
systemd into emergency mode.)

## Image

Any x86-64 disk image with a root filesystem, a running sshd and DHCP on the network adapter
works, for example the Debian cloud image
`https://cloud.debian.org/images/cloud/sid/daily/latest/debian-sid-generic-amd64-daily.raw`.
Simics keeps guest disk writes in memory, so all VMs share the same image and it is never modified.

Install syzkaller's public key for `root` and pre-generate the sshd host keys (every VM boots the
pristine image), e.g. with `virt-customize` from `libguestfs-tools`, which needs no root:

```
ssh-keygen -t ed25519 -N '' -f simics.id_ed25519
printf '[Match]\nName=en* eth*\n\n[Network]\nDHCP=yes\n' > 80-dhcp.network
virt-customize -a image.raw --ssh-inject root:file:simics.id_ed25519.pub \
    --run-command 'ssh-keygen -A' --copy-in 80-dhcp.network:/etc/systemd/network \
    --run-command 'systemctl enable systemd-networkd ssh' \
    --run-command 'systemctl mask apt-daily.timer apt-daily-upgrade.timer man-db.timer'
```

The service node of the QSP targets hands out `10.10.0.100` to the first DHCP client, which is
where the ssh port forward goes (`guest_ip`).

## syzkaller

Build syzkaller as described [here](/docs/linux/setup.md#go-and-syzkaller), then create a manager
config like the following, replacing the paths:

```
{
	"target": "linux/amd64",
	"http": "127.0.0.1:56741",
	"workdir": "/path/to/syzkaller/workdir",
	"kernel_obj": "/path/to/linux-build",
	"image": "/path/to/image.raw",
	"sshkey": "/path/to/simics.id_ed25519",
	"ssh_user": "root",
	"syzkaller": "/path/to/syzkaller",
	"procs": 2,
	"type": "simics",
	"vm": {
		"count": 2,
		"project": "/path/to/simics/project",
		"kernel": "/path/to/linux-build/arch/x86/boot/bzImage",
		"cmdline": "root=/dev/vda1 rw console=ttyS0,115200 earlyprintk=serial,ttyS0,115200 nokaslr oops=panic panic_on_warn=1 panic=86400",
		"params": {
			"machine:hardware:memory_megs": "4096"
		}
	}
}
```

and start it:

```
./bin/syz-manager -config=simics.cfg
```

`syz-manager -mode=smoke-test` boots one round of VMs, runs a few programs and exits, which is a
quick way to check the setup.

## VM config parameters

| parameter       | default                              | meaning |
|-----------------|--------------------------------------|---------|
| `count`         | 1                                    | number of simulator instances |
| `project`       | `$SIMICS_PROJECT`                    | Simics project directory; the simulator runs there |
| `simics`        | `<project>/simics`                   | simulator launcher |
| `simics_args`   | `--no-win --batch-mode`              | launcher options given before the target |
| `target`        | `qsp-x86/user-provided-linux`        | Simics target name or script file |
| `params`        | see below                            | target parameters, passed as `name=value` |
| `kernel`        | none                                 | kernel image (`bzImage`), `{{KERNEL}}` in `params` |
| `cmdline`       | `root=/dev/vda1 rw console=ttyS0,115200 ...` | kernel command line, `{{CMDLINE}}` in `params` |
| `console`       | first `textcon` object by name       | text console carrying the kernel console |
| `ethernet_link` | the only Ethernet link               | link of the guest network adapter |
| `guest_ip`      | `10.10.0.100`                        | guest address the ssh port forward goes to |
| `commands`      | none                                 | extra Simics CLI commands run before the simulation starts |
| `boot_timeout`  | 1800                                 | seconds until the guest has to be reachable over ssh |
| `target_dir`    | `/`                                  | guest directory the fuzzer binaries are copied to |
| `console_log`   | true                                 | save simulator + serial console output of VM N to `<workdir>/simics/vm-N.log`, rewritten on every boot |

In `params` (and `commands`), `{{KERNEL}}`, `{{IMAGE}}` (the manager `image`), `{{CMDLINE}}`,
`{{WORKDIR}}` (the instance directory) and `{{INDEX}}` (the instance index) are substituted.
For the default target these parameters are preset, and `params` is applied on top of them:

```
"machine:software:linux:kernel": "{{KERNEL}}",
"machine:software:linux:virtio_rootfs": "{{IMAGE}}",
"machine:software:linux:cmdline": "{{CMDLINE}}",
"machine:hardware:consoles:con0:show": "FALSE",
"machine:hardware:consoles:gfx_con:create": "FALSE"
```

`./simics <target> -h` in the project lists the parameters of a target, e.g.
`machine:hardware:memory_megs` or `machine:hardware:processor:num_cores`. Other targets work the
same way as long as they have a serial text console, an Ethernet link with a service node and a
guest that gets `guest_ip`: for example `"target": "targets/qsp-x86/qsp-hdd-boot.simics"` with
`"params": {"disk0_image": "{{IMAGE}}"}` boots the kernel installed in the image instead.

## How a VM is started

Every VM is a separate simulator process, started in the project directory with the target and
its parameters:

```
<project>/simics --no-win --batch-mode <target> <param>=<value>...
```

Once the target is loaded, and before the simulation starts, syzkaller prepares the two channels
it needs to the guest:

1. Kernel console. The text console (`console`, by default the first `textcon` object by name)
   stops printing to the simulator command line, keeps its output until a client connects, and
   is opened on a free host TCP port. syzkaller connects to that port and reads the kernel log
   from it during boot and fuzzing.
2. ssh. The service node of the Ethernet link (`ethernet_link`, by default the only one) is told
   to forward a free host port to port 22 of `guest_ip` (`connect-real-network-port-in`).
   Simics prints the port it actually used as `Host TCP port N -> 10.10.0.100:22`; syzkaller takes
   the port from that line, waits until sshd in the guest answers there, and then copies the
   fuzzer binaries and runs all commands over that ssh connection.

Then `commands` run and `run` starts the simulation. `--batch-mode` makes the simulator exit if a
command fails or the simulation stops (e.g. the guest powers off), which ends the VM. The
simulator and console output of VM N goes to `<workdir>/simics/vm-N.log`.

Simics keeps guest disk writes in memory and never writes them back to the image file, so all VMs
share one image. It also decides by itself between VMP and software simulation. syzkaller uses a
slowdown of 10 for this VM type (longer syscall/program/no-output timeouts).

## Measured example

A KASAN + KCOV 7.3 kernel with a Debian sid cloud image on the `qsp-x86/user-provided-linux`
target, software simulation (no `vmxmon` loaded) on an 8-core Intel Core Ultra 7 host:
the guest is reachable over ssh about 2.5 minutes after the simulator starts, and the
`syz-manager -mode=smoke-test` run takes about 4 minutes. With `count` 2, `procs` 2 and
`machine:hardware:memory_megs` 4096, each simulator takes about 1.3 host cores and 2 GB RSS,
and a 20 minute run reached 20k coverage with 8.8k executed programs.

## Troubleshooting

- `simics console: can't connect to the serial console`: the simulator did not start or failed
  while loading the target; the simulator output is in the error and in `<workdir>/simics/vm-N.log`.
- `simics did not report the host port forwarded to guest port 22`: the target has no Ethernet
  link with a service node, or several (set `ethernet_link`).
- `can't ssh into the instance`: the guest did not boot (check the console output for the root
  filesystem or a missing driver), did not get `guest_ip` over DHCP, or sshd rejects the key.
- `SYZFAIL: mount(binfmt_misc) failed`: build `CONFIG_BINFMT_MISC` in.
