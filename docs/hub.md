# Connecting several managers via Hub

`syz-hub` program can be used to connect several `syz-manager`'s together and
allow them to exchange programs.

Build `syz-hub` with `make hub`. Then create a config file along the lines of:

```
{
	"http": ":80",
	"rpc":  ":55555",
	"workdir": "/syzkaller/workdir",
	"clients": [
		{"name": "manager1", "key": "6sCFsJVfyFQVhWVKJpKhHcHxpCH0gAxL"},
		{"name": "manager2", "key": "FZFSjthHHf8nKm2cqqAcAYKM5a3XM4Ao"},
		{"name": "manager3", "key": "fTrIBQCmkEq8NsvQXZiOUyop6uWLBuzf"}
	]
}
```

And start it with `bin/syz-hub -config hub.cfg`. Then add the following
additional parameters to `syz-manager` config files of each manager:

```
	"name": "manager1",
	"hub_client": "manager1",
	"hub_addr": "1.2.3.4:55555",
	"hub_key": "6sCFsJVfyFQVhWVKJpKhHcHxpCH0gAxL",
```

And start managers. Once they triage local corpus, they will connect to the hub
and start exchanging inputs. Both hub and manager web pages will show how many
inputs they send/receive from the hub.
