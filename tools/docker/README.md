# Docker images

We provide a set of Docker images that provide dev environment suitable for syzkaller development/testing.
These images are used by CI, but can also be used for [local development](/docs/contributing.md#using-syz-env).

- [env](/tools/docker/env/Dockerfile) includes Go toolchain, C/C++ cross-compilers, make, git and other essential tools.
- [big-env](/tools/docker/big-env/Dockerfile) includes akaros/fuchsia/netbsd toolchains and gcloud sdk on top of `env` image.
- [old-env](/tools/docker/old-env/Dockerfile) provides essential tools but based on an older disto (ubuntu:16.04).

These images are available as `gcr.io/syzkaller/{env,big-env,old-env}`, respectively.

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

Also upload a copy to Github packages (some users don't have access to `gcr.io`):
```
docker tag gcr.io/syzkaller/env docker.pkg.github.com/google/syzkaller/env
docker login https://docker.pkg.github.com
docker push docker.pkg.github.com/google/syzkaller/env
```
