# syz-agent

`syz-agent` is an AI agent running as part of the continuous fuzzing
infrastructure. It continuously polls the syzbot web dashboard for tasks and
executes agentic workflows.

## Running Locally with Docker

You can easily run `syz-agent` locally without Kubernetes. This is the best
approach for testing and development.

1. Build the Docker image from the root of the syzkaller repository:
   ```bash
   make -C syz-agent container
   ```
   *Note: The default image name is `local/syz-agent:latest`. You can override it by passing `IMAGE_NAME=your-image-name IMAGE_TAG=your-tag`.*

2. Prepare a configuration file (e.g. `config.json`):
   ```json
   {
       "http": ":8080",
       "dashboard_client": "my-local-agent",
       "dashboard_addr": "https://syzkaller.appspot.com",
       "dashboard_key": "YOUR_KEY",
       "target": "linux/amd64",
       "image": "/disk-images/buildroot_amd64",
       "kernel_config": "/kernel-configs/upstream-apparmor-kasan.config",
       "type": "qemu",
       "vm": {
         "cpu": 2,
         "mem": 2048,
         "cmdline": "root=/dev/sda1"
       },
       "cache_size": 107374182400
   }
   ```

3. Run the container, mounting your configuration file:
   ```bash
   docker run -it --rm \
       -p 8080:8080 \
       --privileged \
       -e GOOGLE_API_KEY=$GOOGLE_API_KEY \
       -v $(pwd)/config.json:/etc/syz-agent/config.json:ro \
       local/syz-agent:latest \
       -name=$MY_UNIQUE_AGENT_NAME \
       -config=/etc/syz-agent/config.json
   ```
  *Note: `pkg/updater` is bypassed inside Docker because the
  `-syzkaller=/syzkaller` flag is passed via `run.sh` which serves as the Dockerfile's
  ENTRYPOINT. `syz-agent` will use the pre-built binaries inside the container.*

## Running on Kubernetes

`syz-agent` can be deployed as a `StatefulSet` on Kubernetes (Minikube or GKE) for persistent identity.

### Local Development (Minikube)

To deploy to a standard minikube cluster:

```bash
# 1. Build and load image into Minikube
make container
minikube image load local/syz-agent:latest

# 2. Deploy (automatically binds host's GOOGLE_API_KEY and DASHBOARD_KEY)
GOOGLE_API_KEY=xxx DASHBOARD_KEY=yyy make k8s-minikube | kubectl apply -f -
```
