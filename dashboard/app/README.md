# Dashboard

`dashboard` is an App Engine app that powers [syzbot](/docs/syzbot.md).
The main deployment is at [syzkaller.appspot.com](https://syzkaller.appspot.com).

It is so-called "Standard environment Go app" managed with
[original App Engine SDK](https://cloud.google.com/appengine/docs/standard/go/download).\
For more details about App Engine refer to the [docs](https://cloud.google.com/appengine/docs/)
and in particular [support package docs](https://cloud.google.com/appengine/docs/standard/go/reference).

**Note**: The app is not stable and is not officially supported. It's here only to power the main deployment.
