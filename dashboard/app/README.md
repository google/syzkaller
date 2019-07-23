# Dashboard

`dashboard` is an App Engine app that powers [syzbot](/docs/syzbot.md).
The main deployment is at [syzkaller.appspot.com](https://syzkaller.appspot.com).

It is so-called "Standard environment Go app" managed with
[original App Engine SDK](https://cloud.google.com/appengine/docs/standard/go/download).\
For more details about App Engine refer to the [docs](https://cloud.google.com/appengine/docs/)
and in particular [support package docs](https://cloud.google.com/appengine/docs/standard/go/reference).

**Note**: The app is not stable and is not officially supported. It's here only to power the main deployment.

To test the app one needs to install the SDK and add the `goapp` binary to `$PATH`, then run:
```
goapp test -tags=aetest github.com/google/syzkaller/dashboard/app
```
During development it's handy to use `-short` flag to not run the longest tests.

If any of the tests fail, use `-v` flag to see log of what happens and `-run` flag
to run a single test, e.g.:
```
goapp test -tags=aetest -short -v -run=TestEmailReport github.com/google/syzkaller/dashboard/app
```
