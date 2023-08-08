#!/usr/bin/env bash

# Copyright 2021 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# Rebuilds ci-openbsd in syzkaller project. Helpfully munges the
# .ssh/known_hosts file since the new image has a fresh key.
#
# DROPS files in the current directory, so best used from a subdir of /tmp.
#
# The user is expected to have the private key matching
# the public keys baked into create-openbsd* scripts and a
# section in their .ssh/config similar to this:
#  Host ci-openbsd
#  Hostname ci-openbsd # if running on a project VM or the external IP
#  User syzkaller
#  IdentityFile ~/.ssh/id_syzkaller

# Before running first time do:
# sudo apt-get install genisoimage growisofs qemu qemu-kvm qemu-system-x86-64 expect

# The script does not require any arguments/env vars, run just as:
# $GOPATH/src/github.com/google/syzkaller/dashboard/config/openbsd/recreate.sh

set -eux

TODAY=$(date -u +%Y-%m-%d)

SYZ_DIR="$(cd "$(dirname "${0}")"/../../..; pwd -P)"
[[ -d "${SYZ_DIR}/tools" ]] || { echo "Requires syzkaller dir $SYZ_DIR" ; exit 1; }

ZONE=us-central1-b
INSTANCE=ci-openbsd
IP=$(gcloud compute instances describe "${INSTANCE}" --zone="${ZONE}" --project=syzkaller '--format=text(networkInterfaces[].accessConfigs[].natIP)' | cut -f2 -d' ')
SERVICE_ACCOUNT=$(gcloud compute instances describe "${INSTANCE}" --zone="${ZONE}" --project=syzkaller  '--format=text(serviceAccounts[].email)' | cut -d' ' -f2)
IMAGE="${INSTANCE}"-"${TODAY}"-root

"${SYZ_DIR}"/tools/create-openbsd-gce-ci.sh

gsutil -u syzkaller cp -a public-read openbsd-amd64-snapshot-gce.tar.gz gs://syzkaller/openbsd-amd64-"${TODAY}"-gce.tar.gz

ssh root@"${INSTANCE}" halt -p || true

yes | gcloud compute --project=syzkaller images delete "${IMAGE}" || true
gcloud compute --project=syzkaller images create "${IMAGE}" --source-uri gs://syzkaller/"openbsd-amd64-${TODAY}-gce.tar.gz"

yes | gcloud compute --project=syzkaller instances delete "${INSTANCE}" \
  --zone="${ZONE}"
gcloud compute --project=syzkaller \
  instances create "${INSTANCE}" \
  --address="${IP}" \
  --private-network-ip "${INSTANCE}"-internal \
  --boot-disk-device-name="${INSTANCE}" \
  --boot-disk-size=10GB \
  --boot-disk-type=pd-ssd \
  --disk=name="${INSTANCE}"-syzkaller,device-name="${INSTANCE}"-syzkaller,mode=rw,boot=no \
  --image-project=syzkaller \
  --image="${IMAGE}" \
  --machine-type=custom-12-65536 \
  --maintenance-policy=MIGRATE \
  --metadata=serial-port-enable=1 \
  --network-tier=PREMIUM \
  --scopes=https://www.googleapis.com/auth/cloud-platform \
  --service-account="${SERVICE_ACCOUNT}" \
  --subnet=default \
  --zone="${ZONE}"

(grep -v "^$IP" ~/.ssh/known_hosts && echo "${IP}" "$(grep ssh-ed25519 install_log)") > ~/.ssh/known_hosts.new
mv  ~/.ssh/known_hosts{.new,}

"${SYZ_DIR}"/tools/create-openbsd-vmm-worker.sh

ssh syzkaller@"${INSTANCE}" mkdir -p /syzkaller/userspace
ssh syzkaller@"${INSTANCE}" ln -sf /syzkaller/{gopath/src/github.com/google/syzkaller/dashboard/,}config
scp worker_key syzkaller@"${INSTANCE}":/syzkaller/userspace/key
scp -C worker_disk.raw syzkaller@"${INSTANCE}":/syzkaller/userspace/image
ssh syzkaller@"${INSTANCE}" 'D=/syzkaller/userspace-multicore && mkdir -p $D && ln -sf ../userspace/{image,key} $D && ln -sf ../config/openbsd/overlays/ci-openbsd-multicore $D/overlay'
ssh root@"${INSTANCE}" reboot
