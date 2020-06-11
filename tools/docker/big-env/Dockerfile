# Copyright 2020 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# The image provides dev environment suitable for syzkaller development/testing.
# On top of syz-env it provides akaros/fuchsia/netbsd toolchains and gcloud sdk.

# The image is available as gcr.io/syzkaller/big-env.

# Build as:
# docker build -t gcr.io/syzkaller/big-env tools/docker/big-env

FROM gcr.io/syzkaller/env

# Install OS toolchains from pre-built archives.
# These archives were created with:
# tar -cz --owner=0 --group=0 --mode=go=u -f akaros-toolchain.tar.gz akaros/toolchain
# tar -cz --owner=0 --group=0 --mode=go=u -f netbsd-toolchain.tar.gz netbsd/tools netbsd/dest
# tar -cz --owner=0 --group=0 --mode=go=u -f fuchsia-toolchain.tar.gz fuchsia/prebuilt/third_party/clang \
#	fuchsia/zircon/system/ulib fuchsia/src/lib/ddk fuchsia/out/x64/fidling/gen \
#	fuchsia/out/x64/zircon_toolchain/obj/zircon/public/sysroot/sysroot \
#	fuchsia/out/x64/x64-shared/*.so fuchsia/out/arm64/fidling/gen \
#	fuchsia/out/arm64/zircon_toolchain/obj/zircon/public/sysroot/sysroot \
#	fuchsia/out/arm64/arm64-shared/*.so
#
# And then uploaded to GCS with:
# gsutil mv gs://syzkaller/GOOS-toolchain.tar.gz gs://syzkaller/GOOS-toolchain.old.tar.gz
# gsutil cp GOOS-toolchain.tar.gz gs://syzkaller/
# gsutil acl ch -g all:R gs://syzkaller/GOOS-toolchain.tar.gz
#
# NetBSD toolchain can be re-built with:
# ./build.sh -j72 -m amd64 -U -T ../tools tools
# ./build.sh -j72 -m amd64 -U -T ../tools -D ../dest distribution

RUN curl https://storage.googleapis.com/syzkaller/fuchsia-toolchain.tar.gz | tar -C /syzkaller -xz
RUN curl https://storage.googleapis.com/syzkaller/netbsd-toolchain.tar.gz | tar -C /syzkaller -xz
RUN curl https://storage.googleapis.com/syzkaller/akaros-toolchain.tar.gz | tar -C /syzkaller -xz
ENV SOURCEDIR_FUCHSIA /syzkaller/fuchsia
ENV SOURCEDIR_NETBSD /syzkaller/netbsd
ENV SOURCEDIR_AKAROS /syzkaller/akaros

# Install gcloud sdk for dashboard/app tests.
RUN curl https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-sdk-294.0.0-linux-x86_64.tar.gz | tar -C /usr/local -xz
ENV PATH /usr/local/google-cloud-sdk/bin:$PATH
RUN gcloud components install --quiet app-engine-python app-engine-go cloud-datastore-emulator
RUN chmod 0777 /usr/local/google-cloud-sdk

RUN echo "export PS1='syz-big-env🈶 '" > /syzkaller/.bashrc
ENV SYZ_BIG_ENV yes
