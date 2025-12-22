This dir exists for the purposes of running the dashboard app locally using dev_appserver.py.
The production app sets CWD to the root of the syzkaller repository, so paths that refer to
static resources in app.yaml look like dashboard/app/static/*. However, dev_appserver.py
sets CWD to dashboard/app, so these paths do not work. This dir contains soft link
dashboard/app/dashboard/app/static that point to dashboard/app/static, so that
dashboard/app/static/* paths work from both locations.
