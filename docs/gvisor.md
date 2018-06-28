# gVisor

[gVisor](https://github.com/google/gvisor) is a user-space kernel, written in
Go, that implements a substantial portion of the Linux system surface.

`gVisor` uses `linux` OS, but the special `gvisor` VM type. There is nothing
special regarding `gVisor` besides that. Here is an example manager config:

```
{
	"name": "gvisor",
	"target": "linux/amd64",
	"http": ":12345",
	"workdir": "/workdir",
	"image": "/usr/local/bin/runsc",
	"syzkaller": "/gopath/src/github.com/google/syzkaller",
	"cover": false,
	"procs": 8,
	"type": "gvisor",
	"vm": {
		"count": 5,
		"runsc_args": "-platform=kvm"
	}
}
```
