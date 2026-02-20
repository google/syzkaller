`syz-cluster` is a distributed patch series fuzzing that is relying on syzkaller.
It's deployed at https://ci.syzbot.org.

## Overview

The system is to be deployed on a K8S cluster. The main services are:
* `dashboard`: the web interface, read-only.
* `controller`: manages the state of the system, provides
  [API](./pkg/api/client.go) for other components, schedules fuzzing sessions.
* `series-tracker`: polls LKML git archives for the new series.
* `reporter-server`: generates new reports, provides API for actual reporter
  implementations.
* `email-reporter`: sends reports over email, handles incoming email commands.

The actual patch processing is orchestrated by Argo Workflows: see [the
template](./pkg/workflow/template.yaml). It relies on the following processing
steps:
* `workflow/triage`
* `workflow/build`
* `workflow/boot`
* `workflow/fuzz`

Triage and build steps need the actual kernel checkouts. The base kernel repo is
hosted on a shared network disk and is regularly updated by the scripts in
`kernel-disk`.

The system can be deployed in multiple environments, which is achieved with the
help of Kustomize. Depending on the actual deployment target, different pieces of
configuration are applied:
* `overlays/minikube`: the local dev environment.
* `overlays/gke/staging`: the staging prod environment.
* `overlays/gke/prod`: https://ci.syzbot.org.

`global-config.yaml` is the main configuration file of the system - it
determines the mailing lists to poll, configures resource usage and the actual
reporting.

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
$ eval $(minikube docker-env)
$ make build-all
```
4. Deploy the cluster:
```
$ make restart-spanner
$ kubectl create namespace argo
$ make k8s-config-argo | kubectl apply -f -
$ make k8s-config-argo-wait
$ make k8s-config-dev | kubectl apply -f -
$ make migrate-job.yaml | kubectl create -f -
```
5. Pre-fetch the kernel git repository:
```
$ make fetch-kernels-once.yaml | kubectl create -f -
```

Note that actual series processing won't start until the job created in (5)
finishes.

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
