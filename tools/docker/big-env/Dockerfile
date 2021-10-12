# Copyright 2020 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# See /tools/docker/README.md for details.

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
#
# To build root image run:
#	docker run -it --rm --privileged --device /dev/loop0 gcr.io/syzkaller/big-env
#	mount binfmt_misc -t binfmt_misc /proc/sys/fs/binfmt_misc
#	create-image.sh -a s390x -d buster

RUN dpkg --add-architecture i386 && \
	apt-get update --allow-releaseinfo-change && \
	DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
	# required to build root images.
	debootstrap ssh-tools qemu-user-static \
	# required for gcloud sdk.
	python2 \
	&& \
	apt-get -y autoremove && \
	apt-get clean autoclean && \
	rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*

RUN curl https://storage.googleapis.com/syzkaller/fuchsia-toolchain.tar.gz | tar -C /syzkaller -xz
RUN curl https://storage.googleapis.com/syzkaller/netbsd-toolchain.tar.gz | tar -C /syzkaller -xz
RUN curl https://storage.googleapis.com/syzkaller/akaros-toolchain.tar.gz | tar -C /syzkaller -xz
ENV SOURCEDIR_FUCHSIA /syzkaller/fuchsia
ENV SOURCEDIR_NETBSD /syzkaller/netbsd
ENV SOURCEDIR_AKAROS /syzkaller/akaros

# Install gcloud sdk for dashboard/app tests.
RUN curl https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-sdk-360.0.0-linux-x86_64.tar.gz | tar -C /usr/local -xz
ENV PATH /usr/local/google-cloud-sdk/bin:$PATH
RUN gcloud components install --quiet app-engine-python app-engine-go app-engine-python-extras cloud-datastore-emulator
RUN chmod 0777 /usr/local/google-cloud-sdk

# Install Go 1.12 for local testing of the appengine app build.
# Appengine should be using Go 1.11, but the build fails with 1.11,
# so we use 1.12 as the best working approximation.
RUN go get golang.org/dl/go1.12@latest
# The following command downloads Go into HOME,
# so we need to use HOME value we will be using later.
RUN HOME=/syzkaller go1.12 download

# Debian Buster provides only clang-7 which is quite old,
# in particular it does not detect some warnings that later fire on OpenBSD.
# Install clang-14 from https://apt.llvm.org.
RUN apt-get install -y -q gnupg software-properties-common apt-transport-https
# Without this I am getting error:
# aptsources.distro.NoDistroTemplateException: Error: could not find a distribution template for Debian
RUN apt-get install -y -q --reinstall base-files
RUN curl https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
RUN add-apt-repository "deb http://apt.llvm.org/bullseye/ llvm-toolchain-bullseye main"
RUN apt-get update --allow-releaseinfo-change
RUN apt-get remove -y -q clang-11
RUN apt-get install -y -q --no-install-recommends clang-14
RUN apt autoremove -y -q

RUN echo "export PS1='syz-big-env🈶 '" > /syzkaller/.bashrc
ENV SYZ_BIG_ENV yes
