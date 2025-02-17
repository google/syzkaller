## Local installation steps

1. Install and start minikube: https://minikube.sigs.k8s.io/docs/start/
```
$ minikube start --cni=cilium
```

`--cni=cilium` enables the use of a more advanced Network plugin that supports
the emulation of network policies.

2. Add a Spanner Add-on: https://minikube.sigs.k8s.io/docs/handbook/addons/cloud-spanner/
```
$ minikube addons enable cloud-spanner
```
3. Build all docker containers (might take a while):
```
$ make all-containers
```
4. Deploy the cluster:
```
$ make restart-spanner
$ kubectl create namespace argo
$ kubectl apply -k ./overlays/dev/
```
5. (Optional) Pre-fetch the kernel git repository:
```
kubectl create job --from=cronjob/kernel-repo-update kernel-repo-update-manual
```

## Developmental tips

1. Install Argo Workflows client: https://github.com/argoproj/argo-workflows/releases

Then you can use the `argo` tool like this:

```
$ argo list
```

2. Forward the dashboard port:

```
$ kubectl port-forward service/web-dashboard-service --address 0.0.0.0 50123:80
```
