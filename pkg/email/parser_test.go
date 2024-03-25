// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package email

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestExtractCommand(t *testing.T) {
	for i, test := range extractCommandTests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			cmd, _ := extractCommand(test.body)
			if diff := cmp.Diff(test.cmd, cmd); diff != "" {
				t.Fatal(diff)
			}
			cmd, _ = extractCommand(strings.Replace(test.body, "\n", "\r\n", -1))
			if diff := cmp.Diff(test.cmd, cmd); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestAddRemoveAddrContext(t *testing.T) {
	email := `"Foo Bar" <foo@bar.com>`
	email00, context00, err := RemoveAddrContext(email)
	if err != nil {
		t.Fatal(err)
	}
	if email != email00 {
		t.Fatalf("want: %q, got %q", email, email00)
	}
	if context00 != "" {
		t.Fatalf("want context: %q, got %q", "", context00)
	}
	context1 := "context1"
	email1, err := AddAddrContext(email, context1)
	if err != nil {
		t.Fatal(err)
	}
	want1 := `"Foo Bar" <foo+context1@bar.com>`
	if want1 != email1 {
		t.Fatalf("want: %q, got %q", want1, email1)
	}
	context2 := "context2"
	email2, err := AddAddrContext(email1, context2)
	if err != nil {
		t.Fatal(err)
	}
	want2 := `"Foo Bar" <foo+context1+context2@bar.com>`
	if want2 != email2 {
		t.Fatalf("want: %q, got %q", want2, email2)
	}
	email1, context20, err := RemoveAddrContext(email2)
	if err != nil {
		t.Fatal(err)
	}
	if want1 != email1 {
		t.Fatalf("want: %q, got %q", want1, email1)
	}
	if context2 != context20 {
		t.Fatalf("want context: %q, got %q", context2, context20)
	}
	email0, context10, err := RemoveAddrContext(email1)
	if err != nil {
		t.Fatal(err)
	}
	if email != email0 {
		t.Fatalf("want: %q, got %q", email, email0)
	}
	if context1 != context10 {
		t.Fatalf("want context: %q, got %q", context1, context10)
	}
}

func TestAddAddrContextEmptyName(t *testing.T) {
	email := "<foo@bar.com>"
	email1, err := AddAddrContext(email, "context")
	if err != nil {
		t.Fatal(err)
	}
	if want := "foo+context@bar.com"; want != email1 {
		t.Fatalf("want: %q, got %q", want, email1)
	}
	email2, context1, err := RemoveAddrContext(email1)
	if err != nil {
		t.Fatal(err)
	}
	if email != email2 {
		t.Fatalf("want: %q, got %q", email, email2)
	}
	if context1 != "context" {
		t.Fatalf("got context %q", context1)
	}
}

func TestCanonicalEmail(t *testing.T) {
	canonical := "foo@bar.com"
	emails := []string{
		"\"Foo Bar\" <foo+123+456@Bar.com>",
		"<Foo@bar.com>",
	}
	for _, email := range emails {
		if got := CanonicalEmail(email); got != canonical {
			t.Errorf("got %q, want %q", got, canonical)
		}
	}
}

func TestParse(t *testing.T) {
	for i, test := range parseTests {
		body := func(t *testing.T, test ParseTest) {
			email, err := Parse(strings.NewReader(test.email),
				[]string{"bot <foo@bar.com>"},
				[]string{"list@googlegroups.com"},
				[]string{"bar.com"},
			)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(&test.res, email); diff != "" {
				t.Error(diff)
			}
		}
		t.Run(fmt.Sprint(i), func(t *testing.T) { body(t, test) })

		test.email = strings.Replace(test.email, "\n", "\r\n", -1)
		test.res.Body = strings.Replace(test.res.Body, "\n", "\r\n", -1)
		t.Run(fmt.Sprint(i)+"rn", func(t *testing.T) { body(t, test) })
	}
}

var extractCommandTests = []struct {
	body string
	cmd  *SingleCommand
}{
	{
		body: `Hello,

line1
#syz  fix:  bar baz 	`,
		cmd: &SingleCommand{
			Command: CmdFix,
			Str:     "fix:",
			Args:    "bar baz",
		},
	},
	{
		body: `Hello,

line1
#syz fix  bar  	 baz
line 2
`,
		cmd: &SingleCommand{
			Command: CmdFix,
			Str:     "fix",
			Args:    "bar  	 baz",
		},
	},
	{
		body: `
line1
> #syz fix: bar   baz
line 2
`,
		cmd: nil,
	},
	{
		body: `#syz-fix: bar   baz`,
		cmd: &SingleCommand{
			Command: CmdFix,
			Str:     "fix:",
			Args:    "bar   baz",
		},
	},
	{
		body: `#syz-fix bar   baz`,
		cmd: &SingleCommand{
			Command: CmdFix,
			Str:     "fix",
			Args:    "bar   baz",
		},
	},
	{
		body: `#syz: fix: bar   baz`,
		cmd: &SingleCommand{
			Command: CmdFix,
			Str:     "fix:",
			Args:    "bar   baz",
		},
	},
	// This is unfortunate case when a command is split by email client
	// due to 80-column limitation.
	{
		body: `
#syz test: git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git
locking/core
`,
		cmd: &SingleCommand{
			Command: CmdTest,
			Str:     "test:",
			Args:    "git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git locking/core",
		},
	},
	{
		body: `
#syz test
git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git locking/core
`,
		cmd: &SingleCommand{
			Command: CmdTest,
			Str:     "test",
			// We only look for arguments if there's ":" after "#syz test".
			Args: "",
		},
	},
	{
		body: `
#syz test:
git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git
locking/core
locking/core
`,
		cmd: &SingleCommand{
			Command: CmdTest,
			Str:     "test:",
			Args:    "git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git locking/core",
		},
	},
	{
		body: `#syz test: repo 	commit`,
		cmd: &SingleCommand{
			Command: CmdTest,
			Str:     "test:",
			Args:    "repo commit",
		},
	},
	{
		body: `#syz	test:	repo	commit`,
		cmd: &SingleCommand{
			Command: CmdTest,
			Str:     "test:",
			Args:    "repo commit",
		},
	},
	{
		body: `#syz test
patch-begins
`,
		cmd: &SingleCommand{
			Command: CmdTest,
			Str:     "test",
			Args:    "",
		},
	},
	{
		body: `
#syz test_5_arg_cmd arg1

 arg2  arg3
 
arg4
arg5
`,
		cmd: &SingleCommand{
			Command: cmdTest5,
			Str:     "test_5_arg_cmd",
			Args:    "arg1 arg2 arg3 arg4 arg5",
		},
	},
	{
		body: `#syz test_5_arg_cmd 	arg1	 arg2 	arg3	arg4	 arg5`,
		cmd: &SingleCommand{
			Command: cmdTest5,
			Str:     "test_5_arg_cmd",
			Args:    "arg1 arg2 arg3 arg4 arg5",
		},
	},
	{
		body: `
#syz test_5_arg_cmd arg1
arg2`,
		cmd: &SingleCommand{
			Command: cmdTest5,
			Str:     "test_5_arg_cmd",
			Args:    "arg1 arg2",
		},
	},
	{
		body: `
#syz test_5_arg_cmd arg1
arg2
`,
		cmd: &SingleCommand{
			Command: cmdTest5,
			Str:     "test_5_arg_cmd",
			Args:    "arg1 arg2",
		},
	},
	{
		body: `
#syz test_5_arg_cmd arg1
arg2

 
`,
		cmd: &SingleCommand{
			Command: cmdTest5,
			Str:     "test_5_arg_cmd",
			Args:    "arg1 arg2",
		},
	},
	{
		body: `
#syz fix:
arg1 arg2 arg3
arg4 arg5
 
`,
		cmd: &SingleCommand{
			Command: CmdFix,
			Str:     "fix:",
			Args:    "arg1 arg2 arg3",
		},
	},
	{
		body: `
#syz  fix: arg1 arg2 arg3
arg4 arg5 
`,
		cmd: &SingleCommand{
			Command: CmdFix,
			Str:     "fix:",
			Args:    "arg1 arg2 arg3",
		},
	},
	{
		body: `
#syz dup: title goes here
baz
`,
		cmd: &SingleCommand{
			Command: CmdDup,
			Str:     "dup:",
			Args:    "title goes here",
		},
	},
	{
		body: `
#syz dup 
title on the next line goes here  
but not this one
`,
		cmd: &SingleCommand{
			Command: CmdDup,
			Str:     "dup",
			Args:    "title on the next line goes here",
		},
	},
	{
		body: `
#syz foo bar
baz
`,
		cmd: &SingleCommand{
			Command: CmdUnknown,
			Str:     "foo",
		},
	},
	{
		body: `
#syz set subsystems: net, fs
`,
		cmd: &SingleCommand{
			Command: CmdSet,
			Str:     "set",
			Args:    "subsystems: net, fs",
		},
	},
	{
		body: `
#syz unset some tag
`,
		cmd: &SingleCommand{
			Command: CmdUnset,
			Str:     "unset",
			Args:    "some tag",
		},
	},
	{
		body: `
#syz fix: abcd
#syz fix: xyz
`,
		// Should only extract the first one.
		cmd: &SingleCommand{
			Command: CmdFix,
			Str:     "fix:",
			Args:    "abcd",
		},
	},
}

type ParseTest struct {
	email string
	res   Email
}

var parseTestZone = time.FixedZone("", -7*60*60)

// nolint: lll
var parseTests = []ParseTest{
	{`Date: Sun, 7 May 2017 19:54:00 -0700
Message-ID: <123>
Subject: test subject
From: Bob <bob@example.com>
To: syzbot <foo+4564456@bar.com>
Content-Type: text/plain; charset="UTF-8"

text body
second line
#syz fix: 	 arg1 arg2 arg3 	
last line
-- 
You received this message because you are subscribed to the Google Groups "syzkaller" group.
To unsubscribe from this group and stop receiving emails from it, send an email to syzkaller+unsubscribe@googlegroups.com.
To post to this group, send email to syzkaller@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/syzkaller/abcdef@google.com.
For more options, visit https://groups.google.com/d/optout.`,
		Email{
			BugIDs:    []string{"4564456"},
			MessageID: "<123>",
			Date:      time.Date(2017, time.May, 7, 19, 54, 0, 0, parseTestZone),
			Link:      "https://groups.google.com/d/msgid/syzkaller/abcdef@google.com",
			Subject:   "test subject",
			Author:    "bob@example.com",
			Cc:        []string{"bob@example.com"},
			Body: `text body
second line
#syz fix: 	 arg1 arg2 arg3 	
last line
-- 
You received this message because you are subscribed to the Google Groups "syzkaller" group.
To unsubscribe from this group and stop receiving emails from it, send an email to syzkaller+unsubscribe@googlegroups.com.
To post to this group, send email to syzkaller@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/syzkaller/abcdef@google.com.
For more options, visit https://groups.google.com/d/optout.`,
			Patch: "",
			Commands: []*SingleCommand{
				{
					Command: CmdFix,
					Str:     "fix:",
					Args:    "arg1 arg2 arg3",
				},
			},
		}},

	{`Date: Sun, 7 May 2017 19:54:00 -0700
Message-ID: <123>
Subject: test subject
From: syzbot <foo+4564456@bar.com>
To: Bob <bob@example.com>
Content-Type: text/plain; charset="UTF-8"

text body
last line`,
		Email{
			BugIDs:    []string{"4564456"},
			MessageID: "<123>",
			Date:      time.Date(2017, time.May, 7, 19, 54, 0, 0, parseTestZone),
			Subject:   "test subject",
			Author:    "foo@bar.com",
			OwnEmail:  true,
			Cc:        []string{"bob@example.com"},
			Body: `text body
last line`,
			Patch: "",
		}},

	{`Date: Sun, 7 May 2017 19:54:00 -0700
Message-ID: <123>
Subject: test subject
From: Bob <bob@example.com>
To: syzbot <bot@example.com>, Alice <alice@example.com>

#syz  invalid   	 
text body
second line
last line`,
		Email{
			MessageID: "<123>",
			Date:      time.Date(2017, time.May, 7, 19, 54, 0, 0, parseTestZone),
			Subject:   "test subject",
			Author:    "bob@example.com",
			Cc:        []string{"alice@example.com", "bob@example.com", "bot@example.com"},
			Body: `#syz  invalid   	 
text body
second line
last line`,
			Patch: "",
			Commands: []*SingleCommand{
				{
					Command: CmdInvalid,
					Str:     "invalid",
					Args:    "",
				},
			},
		}},

	{`Date: Sun, 7 May 2017 19:54:00 -0700
Message-ID: <123>
Subject: test subject
From: Bob <bob@example.com>
To: syzbot <bot@example.com>, Alice <alice@example.com>
Content-Type: text/plain

text body
second line
last line
#syz command`,
		Email{
			MessageID: "<123>",
			Date:      time.Date(2017, time.May, 7, 19, 54, 0, 0, parseTestZone),
			Subject:   "test subject",
			Author:    "bob@example.com",
			Cc:        []string{"alice@example.com", "bob@example.com", "bot@example.com"},
			Body: `text body
second line
last line
#syz command`,
			Patch: "",
			Commands: []*SingleCommand{
				{
					Command: CmdUnknown,
					Str:     "command",
				},
			},
		}},

	{`Date: Sun, 7 May 2017 19:54:00 -0700
Message-ID: <123>
Subject: test subject
From: Bob <bob@example.com>
To: syzbot <bot@example.com>
Content-Type: multipart/mixed; boundary="001a114ce0b01684a6054f0d8b81"

--001a114ce0b01684a6054f0d8b81
Content-Type: text/plain; charset="UTF-8"

body text
>#syz test

--001a114ce0b01684a6054f0d8b81
Content-Type: text/x-patch; charset="US-ASCII"; name="patch.patch"
Content-Disposition: attachment; filename="patch.patch"
Content-Transfer-Encoding: base64
X-Attachment-Id: f_j2gwcdoa1

ZGlmZiAtLWdpdCBhL2tlcm5lbC9rY292LmMgYi9rZXJuZWwva2Nvdi5jCmluZGV4IDg1ZTU1NDZj
ZDc5MS4uOTQ5ZWE0NTc0NDEyIDEwMDY0NAotLS0gYS9rZXJuZWwva2Nvdi5jCisrKyBiL2tlcm5l
bC9rY292LmMKQEAgLTEyNyw3ICsxMjcsNiBAQCB2b2lkIGtjb3ZfdGFza19leGl0KHN0cnVjdCB0
YXNrX3N0cnVjdCAqdCkKIAlrY292ID0gdC0+a2NvdjsKIAlpZiAoa2NvdiA9PSBOVUxMKQogCQly
ZXR1cm47Ci0Jc3Bpbl9sb2NrKCZrY292LT5sb2NrKTsKIAlpZiAoV0FSTl9PTihrY292LT50ICE9
IHQpKSB7CiAJCXNwaW5fdW5sb2NrKCZrY292LT5sb2NrKTsKIAkJcmV0dXJuOwo=
--001a114ce0b01684a6054f0d8b81--`,
		Email{
			MessageID: "<123>",
			Date:      time.Date(2017, time.May, 7, 19, 54, 0, 0, parseTestZone),
			Subject:   "test subject",
			Author:    "bob@example.com",
			Cc:        []string{"bob@example.com", "bot@example.com"},
			Body: `body text
>#syz test
`,
			Patch: `diff --git a/kernel/kcov.c b/kernel/kcov.c
index 85e5546cd791..949ea4574412 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -127,7 +127,6 @@ void kcov_task_exit(struct task_struct *t)
 	kcov = t->kcov;
 	if (kcov == NULL)
 		return;
-	spin_lock(&kcov->lock);
 	if (WARN_ON(kcov->t != t)) {
 		spin_unlock(&kcov->lock);
 		return;
`,
		}},

	{`Date: Sun, 7 May 2017 19:54:00 -0700
Message-ID: <123>
Subject: test subject
From: Bob <bob@example.com>
To: syzbot <bot@example.com>
Content-Type: multipart/alternative; boundary="f403043eee70018593054f0d9f1f"

--f403043eee70018593054f0d9f1f
Content-Type: text/plain; charset="UTF-8"

On Mon, May 8, 2017 at 6:47 PM, Bob wrote:
> body text

#syz test

commit 59372bbf3abd5b24a7f6f676a3968685c280f955
Date:   Thu Apr 27 13:54:11 2017 +0200

    statx: correct error handling of NULL pathname

    test patch.

diff --git a/fs/stat.c b/fs/stat.c
index 3d85747bd86e..a257b872a53d 100644
--- a/fs/stat.c
+++ b/fs/stat.c
@@ -567,8 +567,6 @@ SYSCALL_DEFINE5(statx,
  return -EINVAL;
  if ((flags & AT_STATX_SYNC_TYPE) == AT_STATX_SYNC_TYPE)
  return -EINVAL;
- if (!filename)
- return -EINVAL;
 
  error = vfs_statx(dfd, filename, flags, &stat, mask);
  if (error)

--f403043eee70018593054f0d9f1f
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">On Mon, May 8, 2017 at 6:47 PM, Dmitry Vyukov &lt;<a href=
=3D"mailto:bob@example.com">bob@example.com</a>&gt; wrote:<br>&gt; bo=
dy text<br><br>#syz test<br><br><div><div>commit 59372bbf3abd5b24a7f6f67=
6a3968685c280f955</div><div>Date: =C2=A0 Thu Apr 27 13:54:11 2017 +0200</di=
v><div><br></div><div>=C2=A0 =C2=A0 statx: correct error handling of NULL p=
athname</div><div>=C2=A0 =C2=A0=C2=A0</div><div>=C2=A0 =C2=A0 test patch.</=
div><div><br></div><div>diff --git a/fs/stat.c b/fs/stat.c</div><div>index =
3d85747bd86e..a257b872a53d 100644</div><div>--- a/fs/stat.c</div><div>+++ b=
/fs/stat.c</div><div>@@ -567,8 +567,6 @@ SYSCALL_DEFINE5(statx,</div><div>=
=C2=A0<span class=3D"gmail-Apple-tab-span" style=3D"white-space:pre">=09=09=
</span>return -EINVAL;</div><div>=C2=A0<span class=3D"gmail-Apple-tab-span"=
 style=3D"white-space:pre">=09</span>if ((flags &amp; AT_STATX_SYNC_TYPE) =
=3D=3D AT_STATX_SYNC_TYPE)</div><div>=C2=A0<span class=3D"gmail-Apple-tab-s=
pan" style=3D"white-space:pre">=09=09</span>return -EINVAL;</div><div>-<spa=
n class=3D"gmail-Apple-tab-span" style=3D"white-space:pre">=09</span>if (!f=
ilename)</div><div>-<span class=3D"gmail-Apple-tab-span" style=3D"white-spa=
ce:pre">=09=09</span>return -EINVAL;</div><div>=C2=A0</div><div>=C2=A0<span=
 class=3D"gmail-Apple-tab-span" style=3D"white-space:pre">=09</span>error =
=3D vfs_statx(dfd, filename, flags, &amp;stat, mask);</div><div>=C2=A0<span=
 class=3D"gmail-Apple-tab-span" style=3D"white-space:pre">=09</span>if (err=
or)</div></div></div>

--f403043eee70018593054f0d9f1f--`,
		Email{
			MessageID: "<123>",
			Date:      time.Date(2017, time.May, 7, 19, 54, 0, 0, parseTestZone),
			Subject:   "test subject",
			Author:    "bob@example.com",
			Cc:        []string{"bob@example.com", "bot@example.com"},
			Body: `On Mon, May 8, 2017 at 6:47 PM, Bob wrote:
> body text

#syz test

commit 59372bbf3abd5b24a7f6f676a3968685c280f955
Date:   Thu Apr 27 13:54:11 2017 +0200

    statx: correct error handling of NULL pathname

    test patch.

diff --git a/fs/stat.c b/fs/stat.c
index 3d85747bd86e..a257b872a53d 100644
--- a/fs/stat.c
+++ b/fs/stat.c
@@ -567,8 +567,6 @@ SYSCALL_DEFINE5(statx,
  return -EINVAL;
  if ((flags & AT_STATX_SYNC_TYPE) == AT_STATX_SYNC_TYPE)
  return -EINVAL;
- if (!filename)
- return -EINVAL;
 
  error = vfs_statx(dfd, filename, flags, &stat, mask);
  if (error)
`,
			Patch: `diff --git a/fs/stat.c b/fs/stat.c
index 3d85747bd86e..a257b872a53d 100644
--- a/fs/stat.c
+++ b/fs/stat.c
@@ -567,8 +567,6 @@ SYSCALL_DEFINE5(statx,
  return -EINVAL;
  if ((flags & AT_STATX_SYNC_TYPE) == AT_STATX_SYNC_TYPE)
  return -EINVAL;
- if (!filename)
- return -EINVAL;
 
  error = vfs_statx(dfd, filename, flags, &stat, mask);
  if (error)
`,
			Commands: []*SingleCommand{
				{
					Command: CmdTest,
					Str:     "test",
					Args:    "",
				},
			},
		}},

	{`Sender: syzkaller-bugs@googlegroups.com
Subject: Re: BUG: unable to handle kernel NULL pointer dereference in
 sock_poll
To: syzbot <syzbot+344bb0f46d7719cd9483@syzkaller.appspotmail.com>
From: bar <bar@foo.com>
Message-ID: <1250334f-7220-2bff-5d87-b87573758d81@bar.com>
Date: Sun, 10 Jun 2018 10:38:20 +0900
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable

On 2018/06/10 4:57, syzbot wrote:
> Hello,
>=20
> syzbot found the following crash on:
>=20
> HEAD commit: 7d3bf613e99a Merge tag 'libnvdimm-for-4.18=
' of git://git.k..
> git tree: upstream
> console output: https://syzkaller.appspot.com/x/log.txt?x=3D1188a05f80000=
0
> kernel config: https://syzkaller.appspot.com/x/.config?x=3Df04d8d0a=
2afb789a

#syz dup: BUG: unable to handle kernel NULL pointer dereference in corrupte=
d
`, Email{
		MessageID: "<1250334f-7220-2bff-5d87-b87573758d81@bar.com>",
		Date:      time.Date(2018, time.June, 10, 10, 38, 20, 0, time.FixedZone("", 9*60*60)),
		Subject:   "Re: BUG: unable to handle kernel NULL pointer dereference in sock_poll",
		Author:    "bar@foo.com",
		Cc:        []string{"bar@foo.com", "syzbot@syzkaller.appspotmail.com"},
		Body: `On 2018/06/10 4:57, syzbot wrote:
> Hello,
> 
> syzbot found the following crash on:
> 
> HEAD commit: 7d3bf613e99a Merge tag 'libnvdimm-for-4.18' of git://git.k..
> git tree: upstream
> console output: https://syzkaller.appspot.com/x/log.txt?x=1188a05f800000
> kernel config: https://syzkaller.appspot.com/x/.config?x=f04d8d0a2afb789a

#syz dup: BUG: unable to handle kernel NULL pointer dereference in corrupted
`,
		Commands: []*SingleCommand{
			{
				Command: CmdDup,
				Str:     "dup:",
				Args:    "BUG: unable to handle kernel NULL pointer dereference in corrupted",
			},
		},
	}},

	{`Sender: syzkaller-bugs@googlegroups.com
To: syzbot <syzbot+6dd701dc797b23b8c761@syzkaller.appspotmail.com>
From: bar@foo.com

#syz dup:
BUG: unable to handle kernel NULL pointer dereference in corrupted
`, Email{
		Author: "bar@foo.com",
		Cc:     []string{"bar@foo.com", "syzbot@syzkaller.appspotmail.com"},
		Body: `#syz dup:
BUG: unable to handle kernel NULL pointer dereference in corrupted
`,
		Commands: []*SingleCommand{
			{
				Command: CmdDup,
				Str:     "dup:",
				Args:    "BUG: unable to handle kernel NULL pointer dereference in corrupted",
			},
		},
	}},

	{`Sender: syzkaller-bugs@googlegroups.com
To: syzbot <syzbot+6dd701dc797b23b8c761@syzkaller.appspotmail.com>
From: bar@foo.com

#syz fix:
When freeing a lockf struct that already is part of a linked list, make sure to
`, Email{
		Author: "bar@foo.com",
		Cc:     []string{"bar@foo.com", "syzbot@syzkaller.appspotmail.com"},
		Body: `#syz fix:
When freeing a lockf struct that already is part of a linked list, make sure to
`,
		Commands: []*SingleCommand{
			{
				Command: CmdFix,
				Str:     "fix:",
				Args:    "When freeing a lockf struct that already is part of a linked list, make sure to",
			},
		},
	}},
	{`Date: Sun, 7 May 2017 19:54:00 -0700
Message-ID: <123>
Subject: #syz test: git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git master
From: bob@example.com
To: syzbot <foo+4564456@bar.com>

nothing to see here`,
		Email{
			BugIDs:    []string{"4564456"},
			MessageID: "<123>",
			Date:      time.Date(2017, time.May, 7, 19, 54, 0, 0, parseTestZone),
			Subject:   "#syz test: git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git master",
			Author:    "bob@example.com",
			Cc:        []string{"bob@example.com"},
			Body:      `nothing to see here`,
			Commands: []*SingleCommand{
				{
					Command: CmdTest,
					Str:     "test:",
					Args:    "git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git master",
				},
			},
		}},
	{`Date: Sun, 7 May 2017 19:54:00 -0700
Message-ID: <123>
Sender: list@googlegroups.com
Subject: Subject
From: user@mail.com
To: syzbot <list@googlegroups.com>

nothing to see here`,
		Email{
			MessageID:   "<123>",
			Date:        time.Date(2017, time.May, 7, 19, 54, 0, 0, parseTestZone),
			Subject:     "Subject",
			Author:      "user@mail.com",
			MailingList: "list@googlegroups.com",
			Cc:          []string{"list@googlegroups.com", "user@mail.com"},
			Body:        `nothing to see here`,
		}},
	{`Date: Sun, 7 May 2017 19:54:00 -0700
Message-ID: <123>
From: list@googlegroups.com
X-Original-From: user@mail.com
Subject: Subject
To: <user2@mail.com>

nothing to see here`,
		Email{
			MessageID:   "<123>",
			Date:        time.Date(2017, time.May, 7, 19, 54, 0, 0, parseTestZone),
			Subject:     "Subject",
			Author:      "user@mail.com",
			MailingList: "list@googlegroups.com",
			Cc:          []string{"list@googlegroups.com", "user2@mail.com", "user@mail.com"},
			Body:        `nothing to see here`,
		}},
	// A faulty case, just check we handle it normally.
	{`Date: Sun, 7 May 2017 19:54:00 -0700
Message-ID: <123>
From: list@googlegroups.com
Subject: Subject
To: <user2@mail.com>

nothing to see here`,
		Email{
			MessageID:   "<123>",
			Date:        time.Date(2017, time.May, 7, 19, 54, 0, 0, parseTestZone),
			Subject:     "Subject",
			Author:      "list@googlegroups.com",
			MailingList: "list@googlegroups.com",
			Cc:          []string{"list@googlegroups.com", "user2@mail.com"},
			Body:        `nothing to see here`,
		}},
	{`Sender: syzkaller-bugs@googlegroups.com
Subject: Re: BUG: unable to handle kernel NULL pointer dereference in
 sock_poll
To: syzbot <syzbot+344bb0f46d7719cd9483@syzkaller.appspotmail.com>
From: bar <bar@foo.com>
Message-ID: <1250334f-7220-2bff-5d87-b87573758d81@bar.com>
Date: Sun, 7 May 2017 19:54:00 -0700
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable

#syz=20
test: https://github.com/torvalds/linux.git 7b5bb460defa107dd2e82=
f950fddb9ea6bdb5e39
`, Email{
		MessageID: "<1250334f-7220-2bff-5d87-b87573758d81@bar.com>",
		Date:      time.Date(2017, time.May, 7, 19, 54, 0, 0, parseTestZone),
		Subject:   "Re: BUG: unable to handle kernel NULL pointer dereference in sock_poll",
		Author:    "bar@foo.com",
		Cc:        []string{"bar@foo.com", "syzbot@syzkaller.appspotmail.com"},
		Body: `#syz 
test: https://github.com/torvalds/linux.git 7b5bb460defa107dd2e82f950fddb9ea6bdb5e39
`,
		Commands: []*SingleCommand{
			{
				Command: CmdTest,
				Str:     "test:",
				Args:    "https://github.com/torvalds/linux.git 7b5bb460defa107dd2e82f950fddb9ea6bdb5e39",
			},
		},
	}},
	{`Sender: syzkaller-bugs@googlegroups.com
Subject: [PATCH] Some patch
To: <someone@foo.com>
From: bar <bar@foo.com>
Message-ID: <1250334f-7220-2bff-5d87-b87573758d81@bar.com>
Date: Sun, 7 May 2017 19:54:00 -0700
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable

Reported-by: syzbot <foo+223c7461c58c58a4cb10@bar.com>
`, Email{
		BugIDs:    []string{"223c7461c58c58a4cb10"},
		MessageID: "<1250334f-7220-2bff-5d87-b87573758d81@bar.com>",
		Date:      time.Date(2017, time.May, 7, 19, 54, 0, 0, parseTestZone),
		Subject:   "[PATCH] Some patch",
		Author:    "bar@foo.com",
		Cc:        []string{"bar@foo.com", "someone@foo.com"},
		Body: `Reported-by: syzbot <foo+223c7461c58c58a4cb10@bar.com>
`,
	}},
	{`Sender: syzkaller-bugs@googlegroups.com
Subject: [PATCH] Some patch
To: <someone@foo.com>
From: bar <bar@foo.com>
Message-ID: <1250334f-7220-2bff-5d87-b87573758d81@bar.com>
Date: Sun, 7 May 2017 19:54:00 -0700
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US

Link: https://bar.com/bug?extid=223c7461c58c58a4cb10@bar.com
`, Email{
		BugIDs:    []string{"223c7461c58c58a4cb10"},
		MessageID: "<1250334f-7220-2bff-5d87-b87573758d81@bar.com>",
		Date:      time.Date(2017, time.May, 7, 19, 54, 0, 0, parseTestZone),
		Subject:   "[PATCH] Some patch",
		Author:    "bar@foo.com",
		Cc:        []string{"bar@foo.com", "someone@foo.com"},
		Body: `Link: https://bar.com/bug?extid=223c7461c58c58a4cb10@bar.com
`,
	}},

	{`Sender: syzkaller-bugs@googlegroups.com
Subject: [PATCH] Some patch
To: <someone@foo.com>
From: bar <bar@foo.com>
Message-ID: <1250334f-7220-2bff-5d87-b87573758d81@bar.com>
Date: Sun, 7 May 2017 19:54:00 -0700
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable

Reported-by: syzbot <foo+223c7461c58c58a4cb10@bar.com>
Reported-by: syzbot <foo+9909090909090909@bar.com>
`, Email{
		BugIDs:    []string{"223c7461c58c58a4cb10", "9909090909090909"},
		MessageID: "<1250334f-7220-2bff-5d87-b87573758d81@bar.com>",
		Date:      time.Date(2017, time.May, 7, 19, 54, 0, 0, parseTestZone),
		Subject:   "[PATCH] Some patch",
		Author:    "bar@foo.com",
		Cc:        []string{"bar@foo.com", "someone@foo.com"},
		Body: `Reported-by: syzbot <foo+223c7461c58c58a4cb10@bar.com>
Reported-by: syzbot <foo+9909090909090909@bar.com>
`,
	}},
	{`Sender: syzkaller-bugs@googlegroups.com
Subject: [PATCH] Some patch
To: <someone@foo.com>, <foo+9909090909090909@bar.com>
From: bar <bar@foo.com>
Message-ID: <1250334f-7220-2bff-5d87-b87573758d81@bar.com>
Date: Sun, 7 May 2017 19:54:00 -0700
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable

Reported-by: syzbot <foo+223c7461c58c58a4cb10@bar.com>
`, Email{
		// First come BugIDs from header, then from the body.
		BugIDs:    []string{"9909090909090909", "223c7461c58c58a4cb10"},
		MessageID: "<1250334f-7220-2bff-5d87-b87573758d81@bar.com>",
		Date:      time.Date(2017, time.May, 7, 19, 54, 0, 0, parseTestZone),
		Subject:   "[PATCH] Some patch",
		Author:    "bar@foo.com",
		Cc:        []string{"bar@foo.com", "someone@foo.com"},
		Body: `Reported-by: syzbot <foo+223c7461c58c58a4cb10@bar.com>
`,
	}},
	{`Sender: syzkaller-bugs@googlegroups.com
Subject: Some discussion
To: <someone@foo.com>
From: bar <bar@foo.com>
Message-ID: <1250334f-7220-2bff-5d87-b87573758d81@bar.com>
Date: Sun, 7 May 2017 19:54:00 -0700
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <000000000000f1a9d205f909f327@google.com>
 <000000000000ee3a3005f909f30a@google.com>
Precedence: bulk
List-ID: <linux-kernel.vger.kernel.org>
X-Mailing-List: linux-kernel@vger.kernel.org

Some text
`, Email{
		MessageID: "<1250334f-7220-2bff-5d87-b87573758d81@bar.com>",
		// The first one should be picked up.
		InReplyTo: "<000000000000f1a9d205f909f327@google.com>",
		Date:      time.Date(2017, time.May, 7, 19, 54, 0, 0, parseTestZone),
		Subject:   "Some discussion",
		Author:    "bar@foo.com",
		Cc:        []string{"bar@foo.com", "someone@foo.com"},
		Body:      "Some text\n",
	}},
	{`Sender: syzkaller-bugs@googlegroups.com
Subject: Re: BUG: unable to handle kernel NULL pointer dereference in
 sock_poll
To: syzbot <syzbot+344bb0f46d7719cd9483@syzkaller.appspotmail.com>
From: bar <bar@foo.com>
Message-ID: <1250334f-7220-2bff-5d87-b87573758d81@bar.com>
Date: Sun, 7 May 2017 19:54:00 -0700
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable

#syz test: aaa bbb
#syz test: ccc ddd
`, Email{
		MessageID: "<1250334f-7220-2bff-5d87-b87573758d81@bar.com>",
		Date:      time.Date(2017, time.May, 7, 19, 54, 0, 0, parseTestZone),
		Subject:   "Re: BUG: unable to handle kernel NULL pointer dereference in sock_poll",
		Author:    "bar@foo.com",
		Cc:        []string{"bar@foo.com", "syzbot@syzkaller.appspotmail.com"},
		Body: `#syz test: aaa bbb
#syz test: ccc ddd
`,
		Commands: []*SingleCommand{
			{
				Command: CmdTest,
				Str:     "test:",
				Args:    "aaa bbb",
			},
			{
				Command: CmdTest,
				Str:     "test:",
				Args:    "ccc ddd",
			},
		},
	}},
}
