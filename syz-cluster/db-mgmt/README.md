How to run DB migrations locally:

```
cd $SYZKALLER/syz-cluster
make build-db-mgmt-dev restart-spanner
./run-local.sh db-mgmt migrate
```
