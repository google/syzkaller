# Darwin/XNU

It turned out to be unreasonably hard to bootstrap a VM image usable for fuzzing from the XNU source drops without using any of the proprietary kernel extensions shipped with macOS. This guide is therefore based on a normal macOS installation. Unfortunately Apples macOS EULA makes this unsuitable for fuzzing XNU on Google Cloud Platform.

## Prepare a macOS installation disk image

Nowadays Apple mainly distributes macOS updates via the Mac App Store. This will however only give us the latest builds. Luckily the Munki people are kind enough to maintain a script, allowing us to fetch a macOS build of our choice from the shell.

We'll need a macOS build that has a kernel version close to the one we will be building. You can [see Apples most recent source drops on this page](https://opensource.apple.com/). At the time of writing the most recent version is macOS 11.5 containing kernel xnu-7195.141.2. The Munki download script can only tell the macOS version and build number, but not the XNU version. Unfortunately you might occasionally download a matching macOS release, but the kernel you build won't boot anyway. Among many other reasons this can be caused by this mismatch in kernel and bootloader versions. Some trial and error can be involved in getting the correct build. Sometimes the correct build might no longer be available. At the time of writing 11.5 build 20G71 was available and worked with the 11.5 xnu source drop.

In the instructions below I will assume you have VMware Fusion installed on your host macOS for creating the VM disk image. This is for convenience sake as Fusion allows us to simply drag and drop in the macOS installer App we downloaded. If you want to use another tool like Qemu for this, [take note of Apples own process for creating a bootable install media](https://support.apple.com/en-us/HT201372). I had trouble generating bootable ISOs from certain macOS builds using Apples method, hence I just always let Fusion create the installation medium for me.

Additionally the below instructions ask you to disable System Integrity Protection and Authenticated Root inside the VM. We need to do this in order to run the DIY kernel we will build in a bit. Executive Summary on these features:
- In OS X 10.11 Apple introduced System Integrity Protection, a feature that (among other things) limits even root from writing to certain critical system directories during normal operations. We need to disable it to write our kernel to disk
- In macOS 11 Apple introduced Authenticated Root. Starting with this version only a cryptographically signed read only snapshot of the root filesystem is mounted during boot. We need to disable it in order to remount a writable version and take a new snapshot to boot from later

**Tl;Dr: To create the VM image:**
- [Clone Munkis macadmin-script repo](https://github.com/munki/macadmin-scripts)
- Run `installinstallmacos.py` and choose a version matching the last kernel source drop
- Mount and open the downloaded `Install_macOS_<version>-<build>.dmg`
- Open VMware Fusion and create a new VM via the File menu
- Drag and Drop the `Install macOS <name>` App from the mounted disk image into the `Select the Installation Method` Fusion dialog
- I suggest cranking up the VMs CPU and Memory at this point
- After picking your language in the macOS installer open `Utilities -> Terminal`
- Enter `csrutil disable` to disable System Integrity Protection
- Enter `csrutil authenticated-root disable` to disable Authenticated Root
- Quit the Terminal app via Cmd+Q
- Follow through with the macOS installation, creating a user called `user`. If you don’t have any disk available to install to, you might need to use the Disk Utility to format the virtual disk first
- Go to `System Preferences -> Software Update -> Advanced…` and uncheck `Check for updates`
- Go to `System Preferences -> Energy Saver` and check `Prevent computer from sleeping automatically when the display is off`
- Go to `System Preferences -> Sharing` and check `Remote Login` to enable sshd
- Add your ssh pubkey to both your users and roots authorized_keys files
- Optionally disable WindowServer and other non-essential services via launchd. Note that you will obviously loose the GUI: `sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.WindowServer.plist`


Check that everything looks alright:
![screenshot showing clean macos 11.5 build 20G71 installation with xnu-7195.141.2~5/RELEASE_X86_64 and disabled System Integrity Protection, as well as disabled Authenticated Root](https://i.imgur.com/xYJ7XgF.png)


## Prepare a Kernel optimized for fuzzing

You might be wondering why we aren’t using one of the precompiled kernels available in Apples Kernel Development Kits. However those don’t include any kernel built with the KSANCOV feature flag. KSANCOV is Apples take on an API that allows userspace to request the kernel to start tracing which kernel code a given thread touched and exposing that information to userspace. This information is required by Syzkaller to be really effective at fuzzing.

Luckily [afrojer@](https://twitter.com/afrojer) is releasing semi-regularly updated instructions on building XNU from source and installing it on macOS on his blog. At the time of writing he is lagging three minor source drop versions behind. The [most recent instructions are for macOS 11.2](https://web.archive.org/web/20210524205524/https://kernelshaman.blogspot.com/2021/02/building-xnu-for-macos-112-intel-apple.html). We’ll cover some additional required changes in this text.

Building and testing a XNU useful for fuzzing:
- Download a somewhat recent Xcode from [Apples Xcode versions archive (Apple ID login required)](https://developer.apple.com/download/all/?q=xcode) to your VM. I’m using Xcode 12.5. I had issues with 12.5.1 and 13 beta 4
- Open the `Xcode_<version>.xip` to extract. Make a coffee ⏳
- Drag and Drop the extracted Xcode app into your VMs Applications folder
- Start Xcode, agree to the license and quit it after it finishes installation
- Create and join a directory named `kernel` in the users home dir and cd into it
- Downloading afrojer@s Makefile: `curl https://jeremya.com/sw/Makefile.xnudeps > Makefile.xnudeps` Note this file is not versioned, but always updated in place. [Here is an archive link to the version at the time of writing.](https://web.archive.org/web/20210210224511/https://jeremya.com/sw/Makefile.xnudeps)
- `make -f Makefile.xnudeps macos_version=11.5 xnudeps` This will get the dependencies for building the 11.5 XNU. [Check out the original blog post for details on how to fetch dependencies for a specific version](https://kernelshaman.blogspot.com/2021/02/building-xnu-for-macos-112-intel-apple.html)
- cd into `~/kernel/xnu-<version>/`
- Apply [required XNU patches](0001-fuzzing.patch) manually or via `git am`. Applying via git requires you to init the repo and commit all files first. That's probably a good idea anyway to track further changes you might make
    - The patches for `MakeInc.def` and `kasan.c` are required for the KASAN kernel to build. KASAN is short for KernelAddressSANitizer - a feature to detect a bunch of memory safety issues inside the kernel during runtime
    - The `ksancov.h` patch is required for building syzkallers executor. Executor is C++ and hence doesn't like the void pointer casting
    - Finally the `cpuid.c` and `cpu_threads.c` patches are required for our kernel to boot on Qemu

- Run `mount` and look for the roots mount device. On my VM it looks like this `/dev/disk2s5s1 on / (apfs, sealed, local, read-only, journaled)`. Now remember the devices name, ignoring the last sN part. So I note down `/dev/disk2s5`
- Cd into `~/kernel/xnu-<version>/` and run the following, replacing `<your_disk>` to build and install your kernel

```
mkdir -p BUILD/mnt
sudo mount -o nobrowse -t apfs /dev/<your_disk> $PWD/BUILD/mnt

make SDKROOT=macosx TARGET_CONFIGS="KASAN X86_64 NONE" KSANCOV=1

kmutil create -a x86_64 -Z -n boot sys \
-B BUILD/BootKernelExtensions.kc.kasan \
-S BUILD/SystemKernelExtensions.kc.kasan \
-k BUILD/obj/kernel.kasan \
--elide-identifier com.apple.driver.AppleIntelTGLGraphicsFramebuffer

sudo ditto BUILD/BootKernelExtensions.kc.kasan "$PWD/BUILD/mnt/System/Library/KernelCollections/"
sudo ditto BUILD/SystemKernelExtensions.kc.kasan "$PWD/BUILD/mnt/System/Library/KernelCollections/"
sudo ditto BUILD/obj/kernel.kasan "$PWD/BUILD/mnt/System/Library/Kernels/"

sudo bless --folder $PWD/BUILD/mnt/System/Library/CoreServices --bootefi --create-snapshot
sudo nvram boot-args="-v kcsuffix=kasan wlan.skywalk.enable=0"
```

After rebooting you should see your shiny new kernel when running `uname -a`: `Darwin users-Mac.local 20.6.0 Darwin Kernel Version 20.6.0: Mon Aug  9 16:12:43 PDT 2021; user:xnu-7195.141.2/BUILD/obj/KASAN_X86_64 x86_64`


For effective fuzzing we'll need the kernels binary, symbols and source on the host. Copy them like this:

```
mkdir -p ~/115/src/Users/user/kernel/ ~/115/obj
rsync -r mac:/Users/user/kernel/xnu-7195.141.2 ~/115/src/Users/user/kernel/
mv ~/115/src/Users/user/kernel/xnu-7195.141.2/BUILD/obj/KASAN_X86_64/kernel.kasan ~/115/obj/
mv ~/115/src/Users/user/kernel/xnu-7195.141.2/BUILD/obj/KASAN_X86_64/kernel.kasan.dSYM/ ~/115/obj/
```

## Preparing VM for Qemu

Even though Macs are AMD64 machines with EFIs (at least the once we care about here), they aren't exactly IBM PC compatible. So far VMWare Fusion did all the trickery necessary to virtualize macOS for us, but qemu-system-x86_64 does not.

To make macOS boot we'll first start Qemu with OVMF (tianocore based UEFI for qemu). Next we boot OpenCore, which will do some trickery making it possible to chainload Apples stock AMD64 EFI bootloader. It also does some binary kernel patching, making it possible to load the RELEASE kernel shipped with macOS, should we want that.

OpenCore is rather configurable, but we don't care about real hardware. [I'm using this version prebuild and configured to work inside Qemu](https://github.com/thenickdude/KVM-Opencore/releases). We can simply overwrite the EFI partition on our VMs disk with the EFI partition from one of the images from this repo.

Let's first find out which partition we will overwrite in a minute. From the following output from within the macOS VM (still booted via Fusion for now) we can see that in my case the EFI partition is at `/dev/disk0s1`:

```
user@users-Mac ~ % diskutil list
/dev/disk0 (internal, physical):
   #:                       TYPE NAME                    SIZE       IDENTIFIER
   0:      GUID_partition_scheme                        *69.8 GB    disk0
   1:                        EFI EFI                     209.7 MB   disk0s1
   2:                 Apple_APFS Container disk1         69.6 GB    disk0s2

/dev/disk1 (synthesized):
   #:                       TYPE NAME                    SIZE       IDENTIFIER
   0:      APFS Container Scheme -                      +69.6 GB    disk1
                                 Physical Store disk0s2
   1:                APFS Volume macos - Data            43.2 GB    disk1s1
   2:                APFS Volume Preboot                 385.6 MB   disk1s2
   3:                APFS Volume Recovery                623.2 MB   disk1s3
   4:                APFS Volume VM                      1.1 MB     disk1s4
   5:                APFS Volume macos                   16.0 GB    disk1s5
   6:              APFS Snapshot com.apple.bless.4099... 16.0 GB    disk1s5s1
```

Now download [OpenCore-v13.iso.gz](https://github.com/thenickdude/KVM-Opencore/releases/download/v13/OpenCore-v13.iso.gz) and extract the image via `gzip -d OpenCore-v13.iso.gz`. Display the partition map to find out the images blocksize and the EFI partitions offset and size.


```
user@users-Mac ~ % hdiutil pmap ./OpenCore-v13.iso

MEDIA: ""; Size 150 MB [307200 x 512]; Max Transfer Blocks 2048
SCHEME: 1 GPT, "GPT Partition Scheme" [16]
SECTION: 1 Type:'MAP'; Size 150 MB [307200 x 512]; Offset 34 Blocks (307133 + 67) x 512
ID Type                 Offset       Size         Name                      (1)
-- -------------------- ------------ ------------ -------------------- --------
 1 EFI                            40       307120 disk image
```

Now put all those values together in a dd command like so: `sudo dd if=./OpenCore-v13.iso of=/dev/disk0s1 bs=512 iseek=40 count=307120`

Now let's mount the EFI disk via `sudo mount -t msdos /dev/disk0s1 ~/mnt/`. We have to edit OpenCores config file a tiny bit. We disable the boot device selector, as that will prevent us from starting the VMs during fuzzing completely automatically. Additionally note how we set boot-args here. In VMware Fusion we were able to use the normal macOS tools like nvram and csrutil. In OpenCore we need to set these settings in the config.plist instead.

Edit `~/mnt/EFI/OC/config.plist` like so:

```diff
index 8537ca8..a46de97 100755
--- a/Users/user/mnt/EFI/OC/config.plist
+++ b/Users/user/mnt/EFI/OC/config.plist
@@ -799,7 +799,7 @@
 			<key>PollAppleHotKeys</key>
 			<true/>
 			<key>ShowPicker</key>
-			<true/>
+			<false/>
 			<key>TakeoffDelay</key>
 			<integer>0</integer>
 			<key>Timeout</key>
@@ -944,7 +944,7 @@
 				<key>SystemAudioVolume</key>
 				<data>Rg==</data>
 				<key>boot-args</key>
-				<string>keepsyms=1</string>
+				<string>-v kcsuffix=kasan wlan.skywalk.enable=0 keepsyms=1 debug=0x100008 kasan.checks=4294967295</string>
 				<key>csr-active-config</key>
 				<data>Jg8=</data>
 				<key>prev-lang:kbd</key>

```

At this point you should still be able to (re)boot the VM in Fusion. It will just ignore OpenCore however. That's fine.

## Prepare isa-applesmc

On boot macOS checks whether it is booted on a proper Mac by reading a value from its System Management Controller and comparing it with the value it expects. We'll retrieve this value now and pass it to qemu later. To retrieve the value:
- [Download the smc_read.c source from this site.](https://web.archive.org/web/20200603015401/http://www.osxbook.com/book/bonus/chapter7/tpmdrmmyth/)
- `gcc -Wall -o smc_read smc_read.c -framework IOKit`
`./smc_read`

That will produce a single line of text which you will later have to substitute in for a place marked `<YOUR_APPLE_SMC_HERE>`.


## Booting macOS via Qemu

- Setup [Homebrew](https://brew.sh/) on your host macOS
- Install `qemu` via homebrew
- Your VMs disk should be somewhere like this on your host `~/Virtual\ Machines.localized/macOS-11.5-20G71.vmwarevm/Virtual\ Disk.vmdk`. Convert it to qcow2 via something like this `qemu-img convert -U ./Virtual\ Disk.vmdk -O qcow2 ~/115/mac_hdd.qcow`
- Unfortunately OVMF is currently not packaged in Homebrew. Download the [`ovmf` package from ubuntu](https://packages.ubuntu.com/hirsute/ovmf). Extract it via `ar -xv ./ovmf_2020.11-4_all.deb` and `tar -xvf ./data.tar.xz`. Finally `mv ./usr/share/OVMF /usr/local/share/OVMF`

That's pretty much all you should need in order to boot the VM image we build. Start Qemu like so. Remember to substitute `<YOUR_APPLE_SMC_HERE>` and the username in the disk image path:
```
qemu-system-x86_64 \
  -device isa-applesmc,osk="<YOUR_APPLE_SMC_HERE>" \
  -accel hvf -machine q35 -smp "2",cores="2",sockets="1" -m "4096" \
  -cpu Penryn,vendor=GenuineIntel,+invtsc,vmware-cpuid-freq=on,"+pcid,+ssse3,+sse4.2,+popcnt,+avx,+aes,+xsave,+xsaveopt,check" \
  -drive if=pflash,format=raw,readonly=on,file="/usr/local/share/OVMF/OVMF_CODE.fd" \
  -drive if=pflash,format=raw,readonly=on,file="/usr/local/share/OVMF/OVMF_VARS.fd" \
  -device ich9-intel-hda -device hda-duplex -device ich9-ahci,id=sata \
  -device ide-hd,bus=sata.4,drive=MacHDD \
  -drive id=MacHDD,if=none,file="/Users/user/115/macos_11_5.qcow",format=qcow2 \
  -netdev user,id=net0,hostfwd=tcp::1042-:22, -device e1000-82545em,netdev=net0,id=net0 \
  -device usb-ehci,id=ehci -usb -device usb-kbd -device usb-tablet \
  -monitor stdio -vga vmware
```

You should both see the macOS UI and be able to `ssh user@localhost -p 1042`. Confirm we are booted into your KASAN kernel:

```
user@users-Mac ~ % uname -a
Darwin users-Mac.local 20.6.0 Darwin Kernel Version 20.6.0: Mon Aug  9 16:12:43 PDT 2021; user:xnu-7195.141.2/BUILD/obj/KASAN_X86_64 x86_64
```

Shut down your VM now. We'll let syzkaller boot it back up soon.

## Building Syzkaller

- Install `go` via homebrew
- Add something like this to your .zshrc:
```
export GOPATH=/Users/user/go
export PATH=$GOPATH/bin:$PATH
```
- Relogin and build syzkaller like this:
```
git clone https://github.com/google/syzkaller
cd syzkaller
make HOSTOS=darwin HOSTARCH=amd64 TARGETOS=darwin TARGETARCH=amd64 SOURCEDIR=/Users/user/115/src/Users/user/kernel/xnu-7195.141.2
```

## Fuzzing with Syzkaller

- We need g++ to make C reproducers work. Install `gcc@11` via homebrew
- We need addr2line from binutils to make the `/cover` endpoint work. Install `binutils` via homebrew
- Add something like this to your .zshrc `export PATH="/usr/local/opt/binutils/bin:$PATH"`. Restart your shell
- Save the following to `~/115/syzkaller.cfg`. Remember to substitute `<YOUR_APPLE_SMC_HERE>`:
```
{
    "target": "darwin/amd64",
    "http": "127.0.0.1:56741",
    "sshkey": "/Users/user/.ssh/id_macos115",
    "workdir": "/Users/user/sk_darwin/",
    "kernel_obj": "/Users/user/115/obj/",
    "kernel_src": "/Users/user/115/src/",
    "syzkaller": "/Users/user/go/src/github.com/google/syzkaller",
    "procs": 2,
    "type": "qemu",
    "cover": true,
    "image": "/Users/user/115/macos_11_5.qcow",
    "vm": {
        "count": 2,
        "cpu": 2,
        "mem": 4096,
        "efi_code_device": "/usr/local/share/OVMF/OVMF_CODE.fd",
        "efi_vars_device": "/usr/local/share/OVMF/OVMF_VARS.fd",
        "apple_smc_osk": "<YOUR_APPLE_SMC_HERE>"
    }
}
```

Start syzkaller via `~/115/bin/syz-manager -config=/root/115/syzkaller.cfg` and open http://localhost:56741 in your browser.
