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

`"http"` serves the unauthenticated web UI and `/healthz` (keep this internal),
while `"rpc"` serves the authenticated HTTP API (`/api/connect` and `/api/sync`)
for managers. Start it with `bin/syz-hub -config hub.cfg`. For TLS termination
over the public internet, place the `"rpc"` port behind a TLS-terminating
reverse proxy or load balancer.

Then add the following additional parameters to `syz-manager` config files of
each manager:

```
	"name": "manager1",
	"hub_client": "manager1",
	"hub_addr": "https://hub.example.com",
	"hub_key": "6sCFsJVfyFQVhWVKJpKhHcHxpCH0gAxL",
```

`hub_addr` must be an `http://` or `https://` URL (e.g.
`"https://hub.example.com"` or, on trusted private networks only,
`"http://1.2.3.4:55555"`; standard `HTTP_PROXY` / `HTTPS_PROXY` environment
variables are respected). Always use `https://` over untrusted networks so
bearer credentials are encrypted in transit. Leave `hub_key` empty to use
ambient GCE OAuth bearer token authentication.

And start managers. Once they triage local corpus, they will connect to the hub
and start exchanging inputs. Both hub and manager web pages will show how many
inputs they send/receive from the hub.
