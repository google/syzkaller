# Akaros support

[Akaros](http://akaros.cs.berkeley.edu/) support is *incomplete*.

See [Akaros getting started](https://github.com/brho/akaros/blob/master/GETTING_STARTED.md)
re kernel building/running.

Akaros does not support Go at the moment (except for a broken
[1.3 port](https://github.com/akaros/go-akaros)). Full Go support is planned
for Akaros. Until that happens running on Akaros is challening. However,
`syz-stress` can be run as follows:

```shell
make TARGETOS=linux syz-stress
make TARGETOS=akaros SOURCEDIR=/akaros/checkout executor
scp -P 5555 -i akaros_id_rsa -o IdentitiesOnly=yes bin/akaros_amd64/syz-executor  root@localhost:/
bin/linux_amd64/syz-stress -os=akaros -ipc=pipe -procs=8 -executor "/usr/bin/ssh -p 5555 -i akaros_id_rsa -o IdentitiesOnly=yes root@localhost /syz-executor"
```
