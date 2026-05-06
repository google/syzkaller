# Dashboard

`dashboard` is an [App Engine](https://cloud.google.com/appengine) app that powers [syzbot](/docs/syzbot.md).
The main deployment is at [syzkaller.appspot.com](https://syzkaller.appspot.com).

It is so-called [Standard environment](https://cloud.google.com/appengine/docs/standard) Go app.\
To deploy and manage the app you need to install [Google Cloud SDK](https://cloud.google.com/sdk/install).\
For more details about App Engine refer to the [docs](https://cloud.google.com/appengine/docs/standard/go/).

**Note**: The app is not stable and is not officially supported. It's here only to power the main deployment.

Here is "big" picture of a possible setup:
![Overall picture of syzbot setup](/docs/syzbot_architecture.png)

**Note**: the vector source is [here](https://docs.google.com/drawings/d/16EdqYrWD4PWD2nV_PoDPvC5VPry2H40Sm8Min-RtDdA);
to update: make a copy of the source, edit, download a png, update the png and include a link to your vector copy into the PR.

To deploy the app you need to add a `.go` file with production config. The config specifies kernel namespaces,
bug reporting details, API keys, etc. Tests contain a [config example](app_test.go), but it's not ready for
production use.

The app also needs one or more [syz-ci](/syz-ci/syz-ci.go) instances running elsewhere. The `syz-ci` instances
do the actual fuzzing, bisection, patch testing, etc.

The app can be deployed by `gcloud app deploy ./dashboard/app/app.yaml`.

The following optional flags are available:

1. "--no-promote" to test the app firs and migrate the traffic to it later.
2. "--verbosity=info" to see what files are going to be deployed.

The app tests can be run with:
```
go test github.com/google/syzkaller/dashboard/app
```
During development it's handy to use `-short` flag to not run the longest tests.

If any of the tests fail, use `-v` flag to see log of what happens and `-run` flag
to run a single test, e.g.:
```
go test -short -v -run=TestEmailReport github.com/google/syzkaller/dashboard/app
```

## Local Test Deployment

It's possible to run the dashboard locally for testing purposes.
However, note that it won't have any data, so you would need to connect `syz-ci`
instances so that they populate database with some bugs.

First, you need to install Google Cloud SDK (`gcloud` command, and required components,
this is one time step).

Then, create emulator config (this is one time step):

```
gcloud config configurations create emulator
gcloud config set auth/disable_credentials true
gcloud config set project syzkaller
gcloud config set api_endpoint_overrides/spanner http://localhost:9020/
```

Then, start local spanner emulator in one console:

```
gcloud emulators spanner start
gcloud spanner instances create syzbot --config=emulator --nodes=1
gcloud spanner databases create ai --instance=syzbot
```

Then, initialize the schema from another console:

```
for SQL in dashboard/app//aidb/migrations/*.up.sql; do \
	gcloud spanner databases ddl update ai \
	--instance=syzbot --ddl-file ${SQL}; done
```

Finally, start the web server:

```
SPANNER_EMULATOR_HOST="localhost:9010" \
	GOOGLE_CLOUD_SPANNER_MULTIPLEXED_SESSIONS=false \
	google-cloud-sdk/bin/dev_appserver.py --application=syzkaller \
	--host=0.0.0.0 --enable_host_checking=false dashboard/app/
```
