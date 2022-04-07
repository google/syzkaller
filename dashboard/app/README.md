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

The app can be deployed with `GO111MODULE=off gcloud beta app deploy ./dashboard/app/app.yaml` command:
1. GO111MODULE=off is needed to deploy the package, not module.
2. "beta app" instead of "app" is needed to support the "app_engine_apis: true" flag in yaml file.
3. [optional flag] "--no-promote" let you to test the app firs and migrate the traffic to it later.
4. [optional flag] "--verbosity=info" let you to see what files are going to be deployed.

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
