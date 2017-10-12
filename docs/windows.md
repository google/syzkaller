# Windows support

To update descriptions run (assumes `cl` cross-compiler is in PATH):
```
syz-extract -os=windows
syz-sysgen
```

`sys/windows/windows.txt` was auto-extracted from windows headers with `tools/syz-declextract`.

To build binaries:
```
make fuzzer execprog stress TARGETOS=windows
REV=git rev-parse HEAD
cl executor\executor_windows.cc /EHsc -o bin\windows_amd64\syz-executor.exe \
	-DGIT_REVISION=\"$REV\" \
	kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib \
	shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib \
	winmm.lib rpcrt4.lib Crypt32.lib imm32.lib Urlmon.lib Oleaut32.lib \
	Winscard.lib Opengl32.lib Mpr.lib Ws2_32.lib Bcrypt.lib Ncrypt.lib \
	Synchronization.lib Shell32.lib Rpcns4.lib Mswsock.lib  Mincore.lib \
	Msimg32.lib RpcRT4.lib Rpcrt4.lib lz32.lib
```

To run `syz-stress`:
```
bin\windows_amd64\syz-stress.exe -executor c:\full\path\to\bin\windows_amd64\syz-executor.exe
```

Windows is supported by only `gce` VMs at the moment.
To use `gce`, create a Windows GCE VM, inside of the machine:

 - Enable serial console debugging (see [this](https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/boot-parameters-to-enable-debugging) for details):
```
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200 /noumex
```

 - Disable automatic restart in `sysdm.cpl -> Advanced -> Startup and Recovery`

 - Setup sshd with key auth, [these](https://winscp.net/eng/docs/guide_windows_openssh_server) instructions worked for me.
   Preferably use non-admin user. Save private ssh key.

Then shutdown the machine, stop the instance and create an image from the disk.
Then start `syz-manager` with config similar to the following one:

```
{
	"name": "windows",
	"target": "windows/amd64",
	"http": ":20000",
	"workdir": "/workdir",
	"syzkaller": "/syzkaller",
	"sshkey": "/id_rsa",
	"ssh_user": "you",
	"cover": false,
	"procs": 8,
	"type": "gce",
	"vm": {
		"count": 10,
		"machine_type": "n1-highcpu-2",
		"gce_image": "your-gce-image"
	}
}
```
