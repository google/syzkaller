## Local installation steps

1. Install and start minikube: https://minikube.sigs.k8s.io/docs/start/
2. Add a Spanner Add-on: https://minikube.sigs.k8s.io/docs/handbook/addons/cloud-spanner/
3. Build all docker containers:
```
$ make all-containers
```
4. Install Argo Workflows: https://github.com/argoproj/argo-workflows/releases
5. Add a minio bucket (in the local setup it's used by Argo to transfer artifacts):
```
$ argo submit workflows/add-minio-bucket.yaml
```
6. Add Argo workflow templates:
```
$ argo template create workflows/build-step/workflow-template.yaml
$ argo template create workflows/triage-step/workflow-template.yaml
```
7. Deploy the cluster:
```
$ minikube kubectl -- kubectl apply -k ./overlays/dev/
$ make restart-spanner
```
