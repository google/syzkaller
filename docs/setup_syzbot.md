# How to set up syzbot

This doc will be useful to you:
- should you wish to hack on user interface bits like the dashboard / mailing list integration or
- should you wish to continuously run a separate syzbot dashboard for your own kernels

Note: For most development purposes you don't need a full syzbot setup. The meat of syzkaller is really located in syz-manager, syz-fuzzer and syz-executor. You can run syz-manager directly which is usually what you will want to do during fuzzer development. [See this documentation for syz-manager setup instructions](setup.md).

This doc assumes that you:
- have a GCP account and billing setup
- created a GCP project for running syzbot in
- are running a reasonably modern linux distro
- locally installed `gcloud`, `ssh`, `go` and `build-essential`
- may need to install `google-cloud-sdk-app-engine-go` for the GAE deployment to work
- ran `gcloud auth login` to run authenticated gcloud commands
- read [go/syzbot-setup](https://goto.google.com/syzbot-setup) if you are a Googler

While most syzkaller bits happily run on various operating systems, the syzbot dashboard does not. The dashboard is a Google App Engine or GAE project. GAE allows developers to develop web applications without needing to worry about the underlying servers. Instead developers just push their code and GAE takes care of web servers, load balancers and more. Hence this document is more Google Cloud focused than the rest of our documentation.

We will also deploy a syz-ci instance. syz-ci keeps track of the syzkaller and kernel repositories and continuously rebuilds the kernel under test, itself and other syzkaller components when new commits land in the upstream repositories. syz-ci also takes care of (re)starting syz-manager instances, which in turn (re)start VMs fuzzing the target kernel. For simplicity we will run everything in this doc on GCP even though syz-ci could run elsewhere.

![Overall picture of syzbot setup](/docs/syzbot_architecture.png)


## Deploying Syz-ci

[local] First prepare an initial syz-ci build locally (later syz-ci rebuilds itself) and a rootfs:

```sh
# Most syzkaller components can be build even outside of the GOPATH, however
# the syzbot app engine deployment only works from the GOPATH right now..
export GOOGLE_GO=$HOME/gopath/src/github.com/google/
mkdir -p $GOOGLE_GO
git clone https://github.com/google/syzkaller.git
mv syzkaller $GOOGLE_GO/
cd $GOOGLE_GO/syzkaller
make ci

cd ~/repos
git clone git://git.buildroot.net/buildroot
cd buildroot
$GOOGLE_GO/syzkaller/tools/create-buildroot-image.sh
```

[local] Enable various services in the project, create a VM, storage bucket, scp assets and login:

```sh
export PROJECT='your-gcp-project'
export CI_HOSTNAME='ci-linux'
export GOOGLE_GO=$HOME/gopath/src/github.com/google/

gcloud services enable compute.googleapis.com --project="$PROJECT"
gcloud compute instances create "$CI_HOSTNAME" --image-family=debian-11 --image-project=debian-cloud --machine-type=e2-standard-16 --zone=us-central1-a --boot-disk-size=250 --scopes=cloud-platform --project="$PROJECT"

# Enabling compute.googleapis.com created a service account. We allow the syz-ci VM
# to assume the permissions of that service account. As syz-ci needs query / create / delete
# other VMs in the project, we need to give the new service account various permissions
gcloud services enable iam.googleapis.com --project $PROJECT
SERVICE_ACCOUNT=`gcloud iam service-accounts list --filter 'displayName:Compute Engine default service account' --format='value(email)' --project $PROJECT`
gcloud projects add-iam-policy-binding "$PROJECT" --role="roles/editor" --member="serviceAccount:$SERVICE_ACCOUNT" --quiet

gcloud services enable storage-api.googleapis.com --project="$PROJECT"
gsutil mb -p "$PROJECT" "gs://$PROJECT-bucket"

gcloud services enable cloudbuild.googleapis.com --project="$PROJECT"

# We need to wait a bit for the VM to become accessible. Let's just…
sleep 10

# Copy in buildroot
gcloud compute scp --zone us-central1-a --project="$PROJECT" ~/repos/buildroot/output/images/disk.img "$CI_HOSTNAME":~/

# Copy in syz-ci binary
gcloud compute scp --zone us-central1-a --project="$PROJECT" $GOOGLE_GO/syzkaller/bin/syz-ci "$CI_HOSTNAME":~/

# Prepare syz-ci config
cat <<EOF > /tmp/config.ci
{
        "name": "$CI_HOSTNAME",
        "http": ":80",
        "manager_port_start": 50010,
        "syzkaller_repo": "https://github.com/google/syzkaller.git",
        "managers": [
                {
                        "repo": "git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
                        "repo_alias": "upstream",
                        "userspace": "disk.img",
                        "kernel_config": "config/linux/upstream-apparmor-kasan.config",
                        "manager_config": {
                                "name": "ci-upstream-kasan-gce",
                                "target": "linux/amd64",
                                "procs": 6,
                                "type": "gce",
                                "vm": {
                                        "count": 5,
                                        "machine_type": "e2-standard-2",
                                        "gcs_path": "$PROJECT-bucket/disks"
                                },
                                "disable_syscalls": [ "perf_event_open*" ]
                        }
                }
        ]
}
EOF
gcloud compute scp --zone us-central1-a --project="$PROJECT" /tmp/config.ci "$CI_HOSTNAME":~/

# ssh into the syz-ci machine. Will be required in the next step.
gcloud compute ssh "$CI_HOSTNAME" --zone us-central1-a --project="$PROJECT"
```

[syz-ci] Let's install and configure the syz-ci service on our syz-ci VM:

```sh
sudo apt install -y wget git docker.io build-essential

# We need a recent go version, not yet available in debian 11
wget 'https://go.dev/dl/go1.18.linux-amd64.tar.gz'
sudo tar -zxvf go1.18.linux-amd64.tar.gz -C /usr/local/
echo "export PATH=/usr/local/go/bin:${PATH}" | sudo tee /etc/profile.d/go.sh
source /etc/profile.d/go.sh

sudo mkdir /syzkaller
sudo mv ~/syz-ci /syzkaller/
sudo mv ~/disk.img /syzkaller/
sudo mv ~/config.ci /syzkaller/
sudo ln -s /syzkaller/gopath/src/github.com/google/syzkaller/dashboard/config /syzkaller/config

# Pull docker container used by syz-ci for building the linux kernel
# We also do this on systemd start, but the first pull might take a long time,
# resulting in startup timeouts if we don't pull here once first.
sudo /usr/bin/docker pull gcr.io/syzkaller/syzbot

cat <<EOF > /tmp/syz-ci.service
[Unit]
Description=syz-ci
Requires=docker.service
After=docker.service

[Service]
Type=simple
User=root
ExecStartPre=-/usr/bin/docker rm --force syz-ci
ExecStartPre=/usr/bin/docker pull gcr.io/syzkaller/syzbot
ExecStartPre=/usr/bin/docker image prune --filter="dangling=true" -f
# --privileged is required for pkg/osutil sandboxing,
# otherwise unshare syscall fails with EPERM.
# Consider giving it finer-grained permissions,
# or maybe running an unpriv container is better than
# our sandboxing (?) then we could instead add
# --env SYZ_DISABLE_SANDBOXING=yes.
# However, we will also need to build GCE images,
# which requires access to loop devices, mount, etc.
# Proxying /dev is required for image build,
# otherwise partition devices (/dev/loop0p1)
# don't appear inside of the container.
# Host network is required because syz-manager inside
# of the container will create GCE VMs which will
# connect back to the syz-manager using this VM's IP
# and syz-manager port generated inside of the container.
# Without host networking the port is not open on the machine.
ExecStart=/usr/bin/docker run --rm --name syz-ci \
        --privileged \
        --network host \
        --volume /var/run/docker.sock:/var/run/docker.sock \
        --volume /syzkaller:/syzkaller \
        --volume /dev:/dev \
        --workdir /syzkaller \
        --env HOME=/syzkaller \
        gcr.io/syzkaller/syzbot \
        /syzkaller/syz-ci -config config.ci
ExecStop=/usr/bin/docker stop -t 600 syz-ci
Restart=always
RestartSec=10
KillMode=mixed

[Install]
WantedBy=multi-user.target
EOF
sudo mv /tmp/syz-ci.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl restart syz-ci
sudo systemctl enable syz-ci
sudo journalctl -fu syz-ci
```

Check the syc-ci journal logs at this point to see if the service comes up fine. Now syz-ci needs to do a bunch of time consuming stuff like building the kernel under test, so be patient.

If you want to hack on syz-ci you can stop here. Otherwise the next section builds on the syz-ci instructions and extends the setup with a dashboard deployment.

## Deploying Syzbot dashboard

[locally] deploy the dashboard to Google App Engine:

```sh
export PROJECT='your-gcp-project'
export CI_HOSTNAME='ci-linux'
# A random string used by the syz-ci to authenticate against the dashboard
export CI_KEY='fill-with-random-ci-key-string'
# A random string used by the syz-manager to authenticate against the dashboard
export MANAGER_KEY='fill-with-random-manager-key-string'
# A random string used for hashing, can be anything, but once fixed it can't
# be changed as it becomes a part of persistent bug identifiers.
export KEY='fill-with-random-key-string'
# This email will receive all of the crashes found by your instance.
export EMAIL='syzkaller@example.com'

gcloud app create --region us-central --project $PROJECT --quiet

# Grant the app engine service account access to Datastore
SERVICE_ACCOUNT=`gcloud iam service-accounts list --filter 'displayName:App Engine default service account' --format='value(email)' --project $PROJECT`
gcloud projects add-iam-policy-binding "$PROJECT" \
    --member="serviceAccount:$SERVICE_ACCOUNT" \
    --role="roles/editor"
gcloud projects add-iam-policy-binding "$PROJECT" \
    --member="serviceAccount:$SERVICE_ACCOUNT" \
    --role="roles/datastore.owner"

GOOGLE_GO=$HOME/gopath/src/github.com/google/
cd $GOOGLE_GO/syzkaller

# Enable some crons for sending emails and such
gcloud services enable cloudscheduler.googleapis.com --project $PROJECT
gcloud app deploy ./dashboard/app/cron.yaml --project $PROJECT --quiet

# Create required Datastore indexes. Requires a few minutes to
# generate before they (and hence syzbot) become usable
gcloud datastore indexes create ./dashboard/app/index.yaml --project $PROJECT --quiet

cat <<EOF > ./dashboard/app/config_not_prod.go
package main
import (
        "time"
        "github.com/google/syzkaller/dashboard/dashapi"
)
const (
        reportingUpstream    = "upstream"
        moderationDailyLimit = 30
        internalDailyLimit   = 30
        reportingDelay       = 0
        domainLinux          = "linux"
)
func init() {
        checkConfig(prodConfig)
        mainConfig = prodConfig
}
var prodConfig = &GlobalConfig{
        AccessLevel:         AccessPublic,
        AuthDomain:          "@google.com",
        CoverPath:           "https://storage.googleapis.com/syzkaller/cover/",
        Clients: map[string]string{
                "$CI_HOSTNAME":     "$CI_KEY",
        },
        Obsoleting: ObsoletingConfig{
                MinPeriod:         90 * 24 * time.Hour,
                MaxPeriod:         120 * 24 * time.Hour,
                NonFinalMinPeriod: 60 * 24 * time.Hour,
                NonFinalMaxPeriod: 90 * 24 * time.Hour,
        },
        DefaultNamespace: "upstream",
        Namespaces: map[string]*Config{
                "upstream": {
                        AccessLevel:      AccessPublic,
                        DisplayTitle:     "Linux",
                        SimilarityDomain: domainLinux,
                        Key:              "$KEY",
                        Clients: map[string]string{
                                "ci-upstream-kasan-gce":  "$MANAGER_KEY",
                        },
                        Repos: []KernelRepo{
                                {
                                        URL:               "git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
                                        Branch:            "master",
                                        Alias:             "upstream",
                                        ReportingPriority: 9,
                                },
                        },
                        MailWithoutReport: true,
                        ReportingDelay:    reportingDelay,
                        WaitForRepro:      0,
                        Managers: map[string]ConfigManager{},
                        Reporting: []Reporting{
                                {
                                        AccessLevel: AccessPublic,
                                        Name:        reportingUpstream,
                                        DailyLimit:  30,
                                        Config: &EmailConfig{
                                                Email:              "$EMAIL",
                                                SubjectPrefix:      "[syzbot-test]",
                                                MailMaintainers:    false,
                                        },
                                },
                        },
                        TransformCrash: func(build *Build, crash *dashapi.Crash) bool {
                                return true
                        },
                        NeedRepro: func(bug *Bug) bool {
                                return true
                        },
                },
        },
}
EOF

# Deploy the actual dashboard GAE application
GOPATH=~/gopath GO111MODULE=off gcloud beta app deploy ./dashboard/app/app.yaml --project "$PROJECT" --quiet
```

### Integrating Syz-ci with syzbot

[locally] Prepare config and login to syz-ci VM:

```sh
export PROJECT='your-gcp-project'
export CI_HOSTNAME='ci-linux'
export CI_KEY='fill-with-random-ci-key-string'
export MANAGER_KEY='fill-with-random-manager-key-string'
export DASHBOARD_FQDN=`gcloud app describe --project $PROJECT --format 'value(defaultHostname)'`

cat <<EOF > /tmp/config.ci
{
        "name": "$CI_HOSTNAME",
        "http": ":80",
        "manager_port_start": 50010,
        "dashboard_addr": "https://$DASHBOARD_FQDN",
        "dashboard_client": "$CI_HOSTNAME",
        "dashboard_key": "$CI_KEY",
        "syzkaller_repo": "https://github.com/google/syzkaller.git",
        "managers": [
                {
                        "repo": "git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
                        "repo_alias": "upstream",
                        "dashboard_client": "ci-upstream-kasan-gce",
                        "dashboard_key": "$MANAGER_KEY",
                        "userspace": "disk.img",
                        "kernel_config": "config/linux/upstream-apparmor-kasan.config",
                        "manager_config": {
                                "name": "ci-upstream",
                                "target": "linux/amd64",
                                "procs": 6,
                                "type": "gce",
                                "vm": {
                                        "count": 5,
                                        "machine_type": "e2-standard-2",
                                        "gcs_path": "$PROJECT-bucket/disks"
                                },
                                "disable_syscalls": [ "perf_event_open*" ]
                        }
                }
        ]
}
EOF
gcloud compute scp --zone us-central1-a --project="$PROJECT" /tmp/config.ci "$CI_HOSTNAME":~/

gcloud compute ssh "$CI_HOSTNAME" --zone us-central1-a --project="$PROJECT"
```

[syz-ci] Reconfigure syz-ci to start sending results to the dashboard:

```sh
sudo mv ~/config.ci /syzkaller/
sudo systemctl restart syz-ci
sudo journalctl -fu syz-ci
```

[locally] Open the dashboard in your browser:
```
gcloud app browse --project=$PROJECT
```
Once syzkaller finds the first crashes they should show up here. This might take a while.