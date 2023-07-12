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

To build and push a new version:
```
docker build -t gcr.io/syzkaller/env tools/docker/env
gcloud auth login && gcloud auth configure-docker
docker push gcr.io/syzkaller/env
```

[DEPRECATED] Github packages are not supported (if you can't access gcr.io, please contact us)
```
docker tag gcr.io/syzkaller/env docker.pkg.github.com/google/syzkaller/env
docker login https://docker.pkg.github.com
docker push docker.pkg.github.com/google/syzkaller/env
```

## Syzbot image

The syzbot image supports two architectures (arm64, amd64), so we need to build it with care.

The example below uses [the standard Docker functionality](https://docs.docker.com/build/building/multi-platform/) to build a
multi-arch image in a way that allows to distribute it under one tag names.

```bash
docker run --privileged --rm tonistiigi/binfmt --install all
docker buildx create --name mybuilder --driver docker-container --bootstrap
docker buildx use mybuilder
gcloud auth login && gcloud auth configure-docker
docker buildx build --platform linux/amd64,linux/arm64 -t gcr.io/syzkaller/syzbot tools/docker/syzbot --push
```
