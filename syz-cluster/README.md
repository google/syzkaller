## Local installation steps

1. Install and start minikube: https://minikube.sigs.k8s.io/docs/start/
```
$ minikube start
```
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
$ kubectl create namespace argo
$ minikube kubectl -- kubectl apply -k ./overlays/dev/
$ argo template create workflow/*/workflow-template.yaml
$ make restart-spanner
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
