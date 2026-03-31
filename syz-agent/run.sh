#!/bin/bash
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.


if [ "$GIT_COOKIE_DAEMON" = "1" ]; then
    # Start git-cookie-authdaemon in the background as syzkaller user.
    # It will update cookies in /home/syzkaller/.git-credential-cache/cookie
    # We use sudo -u syzkaller and set HOME explicitly.
    sudo -u syzkaller HOME=/home/syzkaller /app/git-cookie-authdaemon --nofork &
fi

# Start syz-agent as the foreground process.
exec /app/syz-agent -syzkaller=/syzkaller "$@"
