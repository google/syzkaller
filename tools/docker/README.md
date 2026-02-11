# Docker images

We provide a set of Docker images that provide dev environment suitable for syzkaller development/testing.
These images are used by CI, but can also be used for [local development](/docs/contributing.md#using-syz-env).

- [env](/tools/docker/env/Dockerfile) includes Go/fuchsia/netbsd toolchains, gcloud sdk, C/C++ cross-compilers, make, git and other essential tools.
- [old-env](/tools/docker/old-env/Dockerfile) provides essential tools but based on an older disto (ubuntu:16.04).

These images are available as `gcr.io/syzkaller/{env,old-env}`, respectively.

To download and run locally:
```
docker pull gcr.io/syzkaller/env
docker run -it gcr.io/syzkaller/env
```

## Building Multi-arch Images

The `syzbot` and `env` images support multiple architectures (amd64, arm64). To build and push them, we use [Docker buildx](https://docs.docker.com/build/building/multi-platform/) to build a multi-arch image in a way that allows distributing it under one tag name.

### 1. One-time Setup

Install the QEMU emulators and create a new builder instance:

```bash
# Install QEMU emulators for multi-arch support
docker run --privileged --rm tonistiigi/binfmt --install all

# Create and bootstrap a new builder
docker buildx create --name mybuilder --driver docker-container --bootstrap
docker buildx use mybuilder
```

### 2. Build and Push

Once the builder is configured, you can build and push the images. Ensure you are authenticated with Google Cloud:

```bash
gcloud auth login && gcloud auth configure-docker
```

**Building the `syzbot` image:**

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -t gcr.io/syzkaller/syzbot \
  tools/docker/syzbot \
  --push
```

**Building the `env` image:**

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -t gcr.io/syzkaller/env \
  tools/docker/env \
  --push
```

## [DEPRECATED] Github Packages

Github packages are not supported (if you can't access gcr.io, please contact us).

```
docker tag gcr.io/syzkaller/env [docker.pkg.github.com/google/syzkaller/env](https://docker.pkg.github.com/google/syzkaller/env)
docker login [https://docker.pkg.github.com](https://docker.pkg.github.com)
docker push [docker.pkg.github.com/google/syzkaller/env](https://docker.pkg.github.com/google/syzkaller/env)
```
