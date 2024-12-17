To update and access the web dashboard during local development:

```
$ make install-dev-config
$ make deploy-web-dashboard-dev
$ kubectl port-forward service/web-dashboard-service --address 0.0.0.0 50123:80
```
