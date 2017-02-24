// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dash

import (
	"testing"
)

func TestParsePatch(t *testing.T) {
	for _, test := range tests {
		t.Run(test.title, func(t *testing.T) {
			title, diff, err := parsePatch(test.text)
			if err != nil {
				t.Fatalf("failed to parse patch: %v", err)
			}
			if test.title != title {
				t.Fatalf("title mismatch, want:\n%v\ngot:\n%v", test.title, title)
			}
			if test.diff != diff {
				t.Fatalf("diff mismatch, want:\n%v\ngot:\n%v", test.diff, diff)
			}
		})
	}
}

var tests = []struct {
	text  string
	title string
	diff  string
}{
	{
		text: `
commit 7bdb59aaaaaa4bd7161adc8f923cdef10f2638d1
Author: Some foo-bar áš <foo@bar.com>
Date:   Tue Feb 7 17:44:54 2017 +0100

    net/tcp: fix foo()
    
    foo->bar is wrong.
    Fix foo().
    
    More description.
    
    Signed-off-by: Some foo-bar áš <foo@bar.com>
    Reviewed: Some foo-bar <foo@bar.com>
    Link: http://lkml.kernel.org/r/123123123123-123-1-git-send-email-foo@bar.com

diff --git a/kernel/time/tick-sched.c b/kernel/time/tick-sched.c
index 74e0388cc88d..fc6f740d0277 100644
--- a/kernel/time/tick-sched.c
+++ b/kernel/time/tick-sched.c
@@ -725,6 +725,11 @@ static ktime_t tick_nohz_stop_sched_tick(struct tick_sched *ts,
 		 */
 		if (delta == 0) {
 			tick_nohz_restart(ts, now);
+			/*
+			 * Make sure next tick stop doesn't get fooled by past
+			 * clock deadline
+			 */
+			ts->next_tick = 0;
 			goto out;
 		}
 	}
`,
		title: "net/tcp: fix foo()",
		diff: `--- a/kernel/time/tick-sched.c
+++ b/kernel/time/tick-sched.c
@@ -725,6 +725,11 @@ static ktime_t tick_nohz_stop_sched_tick(struct tick_sched *ts,
 		 */
 		if (delta == 0) {
 			tick_nohz_restart(ts, now);
+			/*
+			 * Make sure next tick stop doesn't get fooled by past
+			 * clock deadline
+			 */
+			ts->next_tick = 0;
 			goto out;
 		}
 	}
`,
	},

	{
		text: `
fix looking up invalid subclass: 4294967295

diff --git a/net/irda/irqueue.c b/net/irda/irqueue.c
index acbe61c..160dc89 100644
--- a/net/irda/irqueue.c
+++ b/net/irda/irqueue.c
@@ -383,9 +383,6 @@ EXPORT_SYMBOL(hashbin_new);
  *    for deallocating this structure if it's complex. If not the user can
  *    just supply kfree, which should take care of the job.
  */
-#ifdef CONFIG_LOCKDEP
-static int hashbin_lock_depth = 0;
-#endif
 int hashbin_delete( hashbin_t* hashbin, FREE_FUNC free_func)
 {
 	irda_queue_t* queue;
`,
		title: "fix looking up invalid subclass: 4294967295",
		diff: `--- a/net/irda/irqueue.c
+++ b/net/irda/irqueue.c
@@ -383,9 +383,6 @@ EXPORT_SYMBOL(hashbin_new);
  *    for deallocating this structure if it's complex. If not the user can
  *    just supply kfree, which should take care of the job.
  */
-#ifdef CONFIG_LOCKDEP
-static int hashbin_lock_depth = 0;
-#endif
 int hashbin_delete( hashbin_t* hashbin, FREE_FUNC free_func)
 {
 	irda_queue_t* queue;
`,
	},

	{
		text: `net: fix looking up invalid subclass: 4294967295
diff --git a/net/irda/irqueue.c b/net/irda/irqueue.c
index acbe61c..160dc89 100644
--- a/net/irda/irqueue.c
+++ b/net/irda/irqueue.c
@@ -383,9 +383,6 @@ EXPORT_SYMBOL(hashbin_new);
  *    for deallocating this structure if it's complex. If not the user can
  *    just supply kfree, which should take care of the job.
  */
-#ifdef CONFIG_LOCKDEP
-static int hashbin_lock_depth = 0;
-#endif
 int hashbin_delete( hashbin_t* hashbin, FREE_FUNC free_func)`,
		title: "net: fix looking up invalid subclass: 4294967295",
		diff: `--- a/net/irda/irqueue.c
+++ b/net/irda/irqueue.c
@@ -383,9 +383,6 @@ EXPORT_SYMBOL(hashbin_new);
  *    for deallocating this structure if it's complex. If not the user can
  *    just supply kfree, which should take care of the job.
  */
-#ifdef CONFIG_LOCKDEP
-static int hashbin_lock_depth = 0;
-#endif
 int hashbin_delete( hashbin_t* hashbin, FREE_FUNC free_func)
`,
	},

	{
		text: `
Delivered-To: foo@bar.com
Date: Tue, 31 Jan 2017 15:24:03 +0100 (CET)
To: Foo Bar <foo@bar.com>
Subject: [PATCH v2] timerfd: Protect the might cancel mechanism proper
MIME-Version: 1.0
Content-Type: text/plain; charset=US-ASCII

The handling of the might_cancel queueing is not properly protected, so
parallel operations on the file descriptor can race with each other and
lead to list corruptions or use after free.

Protect the context for these operations with a seperate lock.

Reported-by: Foo Bar <foo@bar.com>
Signed-off-by: Foo Bar <foo@bar.com>
---
 fs/timerfd.c |   17 ++++++++++++++---
 1 file changed, 14 insertions(+), 3 deletions(-)

--- a/fs/timerfd.c
+++ b/fs/timerfd.c
@@ -40,6 +40,7 @@ struct timerfd_ctx {
 	short unsigned settime_flags;	/* to show in fdinfo */
 	struct rcu_head rcu;
 	struct list_head clist;
+	spinlock_t cancel_lock;
 	bool might_cancel;
 };
`,
		title: "timerfd: Protect the might cancel mechanism proper",
		diff: `--- a/fs/timerfd.c
+++ b/fs/timerfd.c
@@ -40,6 +40,7 @@ struct timerfd_ctx {
 	short unsigned settime_flags;	/* to show in fdinfo */
 	struct rcu_head rcu;
 	struct list_head clist;
+	spinlock_t cancel_lock;
 	bool might_cancel;
 };
`,
	},

	{
		text: `crypto/sha512-mb: Correct initialization value for lane lens
diff --git a/arch/x86/crypto/sha512-mb/sha512_mb_mgr_init_avx2.c b/arch/x86/crypto/sha512-mb/sha512_mb_mgr_init_avx2.c
index 36870b2..5484d77 100644
--- a/arch/x86/crypto/sha512-mb/sha512_mb_mgr_init_avx2.c
+++ b/arch/x86/crypto/sha512-mb/sha512_mb_mgr_init_avx2.c
@@ -57,10 +57,10 @@ void sha512_mb_mgr_init_avx2(struct sha512_mb_mgr *state)
 {
 	unsigned int j;
 
-	state->lens[0] = 0;
-	state->lens[1] = 1;
-	state->lens[2] = 2;
-	state->lens[3] = 3;
+	state->lens[0] = 0xFFFFFFFF00000000;
+	state->lens[1] = 0xFFFFFFFF00000001;
+	state->lens[2] = 0xFFFFFFFF00000002;
+	state->lens[3] = 0xFFFFFFFF00000003;
 	state->unused_lanes = 0xFF03020100;
 	for (j = 0; j < 4; j++)
 		state->ldata[j].job_in_lane = NULL;
-- 
2.5.5`,
		title: "crypto/sha512-mb: Correct initialization value for lane lens",
		diff: `--- a/arch/x86/crypto/sha512-mb/sha512_mb_mgr_init_avx2.c
+++ b/arch/x86/crypto/sha512-mb/sha512_mb_mgr_init_avx2.c
@@ -57,10 +57,10 @@ void sha512_mb_mgr_init_avx2(struct sha512_mb_mgr *state)
 {
 	unsigned int j;
 
-	state->lens[0] = 0;
-	state->lens[1] = 1;
-	state->lens[2] = 2;
-	state->lens[3] = 3;
+	state->lens[0] = 0xFFFFFFFF00000000;
+	state->lens[1] = 0xFFFFFFFF00000001;
+	state->lens[2] = 0xFFFFFFFF00000002;
+	state->lens[3] = 0xFFFFFFFF00000003;
 	state->unused_lanes = 0xFF03020100;
 	for (j = 0; j < 4; j++)
 		state->ldata[j].job_in_lane = NULL;
`,
	},

	{
		text: `
Subject: [Patch net] kcm: fix a null pointer dereference in kcm_sendmsg()

--- a/fs/timerfd.c
+++ b/fs/timerfd.c
@@ -40,6 +40,7 @@ struct timerfd_ctx {
 	short unsigned settime_flags;	/* to show in fdinfo */
 	struct rcu_head rcu;
 	struct list_head clist;
+	spinlock_t cancel_lock;
 	bool might_cancel;
 };
`,
		title: "kcm: fix a null pointer dereference in kcm_sendmsg()",
		diff: `--- a/fs/timerfd.c
+++ b/fs/timerfd.c
@@ -40,6 +40,7 @@ struct timerfd_ctx {
 	short unsigned settime_flags;	/* to show in fdinfo */
 	struct rcu_head rcu;
 	struct list_head clist;
+	spinlock_t cancel_lock;
 	bool might_cancel;
 };
`,
	},

	{
		text: `
Subject: Re: [PATCH v3] net/irda: fix lockdep annotation

--- a/fs/timerfd.c
+++ b/fs/timerfd.c
@@ -40,6 +40,7 @@ struct timerfd_ctx {
 	short unsigned settime_flags;	/* to show in fdinfo */
 	struct rcu_head rcu;
 	struct list_head clist;
+	spinlock_t cancel_lock;
 	bool might_cancel;
 };
`,
		title: "net/irda: fix lockdep annotation",
		diff: `--- a/fs/timerfd.c
+++ b/fs/timerfd.c
@@ -40,6 +40,7 @@ struct timerfd_ctx {
 	short unsigned settime_flags;	/* to show in fdinfo */
 	struct rcu_head rcu;
 	struct list_head clist;
+	spinlock_t cancel_lock;
 	bool might_cancel;
 };
`,
	},

	{
		text: `syz-dash: first version of dashboard app
diff --git a/syz-dash/api.go b/syz-dash/api.go
new file mode 100644
index 0000000..a1a0499
--- /dev/null
+++ b/syz-dash/api.go
@@ -0,0 +1,444 @@
+package dash
`,
		title: "syz-dash: first version of dashboard app",
		diff: `--- /dev/null
+++ b/syz-dash/api.go
@@ -0,0 +1,444 @@
+package dash
`,
	},
}
