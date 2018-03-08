// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package email

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestExtractCommand(t *testing.T) {
	for i, test := range extractCommandTests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			cmd, args := extractCommand([]byte(test.body))
			if cmd != test.cmd || !reflect.DeepEqual(args, test.args) {
				t.Logf("expect: %q %q", test.cmd, test.args)
				t.Logf("got   : %q %q", cmd, args)
				t.Fail()
			}
			cmd, args = extractCommand([]byte(strings.Replace(test.body, "\n", "\r\n", -1)))
			if cmd != test.cmd || !reflect.DeepEqual(args, test.args) {
				t.Logf("expect: %q %q", test.cmd, test.args)
				t.Logf("got   : %q %q", cmd, args)
				t.Fail()
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
			email, err := Parse(strings.NewReader(test.email), []string{"bot <foo@bar.com>"})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(email, &test.res) {
				t.Logf("expect:\n%#v", &test.res)
				t.Logf("got:\n%#v", email)
				t.Fail()
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
	cmd  string
	args string
}{
	{
		body: `Hello,

line1
#syz  fix:  bar baz 	`,
		cmd:  "fix:",
		args: "bar baz",
	},
	{
		body: `Hello,

line1
#syz fix:  bar  	 baz
line 2
`,
		cmd: "fix:",
		args: "bar  	 baz",
	},
	{
		body: `
line1
> #syz fix: bar   baz
line 2
`,
		cmd:  "",
		args: "",
	},
	// This is unfortunate case when a command is split by email client
	// due to 80-column limitation.
	{
		body: `
#syz test: git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git
locking/core
`,
		cmd:  "test:",
		args: "git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git locking/core",
	},
	{
		body: `
#syz test:
git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git locking/core
`,
		cmd:  "test:",
		args: "git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git locking/core",
	},
	{
		body: `
#syz test:
git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git
locking/core
locking/core
`,
		cmd:  "test:",
		args: "git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git locking/core",
	},
	{
		body: `
#syz test_5_arg_cmd arg1

 arg2  arg3
 
arg4
arg5
`,
		cmd:  "test_5_arg_cmd",
		args: "arg1 arg2 arg3 arg4 arg5",
	},
	{
		body: `
#syz test_5_arg_cmd arg1
arg2`,
		cmd:  "test_5_arg_cmd",
		args: "arg1 arg2",
	},
	{
		body: `
#syz test_5_arg_cmd arg1
arg2
`,
		cmd:  "test_5_arg_cmd",
		args: "arg1 arg2",
	},
	{
		body: `
#syz test_5_arg_cmd arg1
arg2

 
`,
		cmd:  "test_5_arg_cmd",
		args: "arg1 arg2",
	},
	{
		body: `
#syz fix:
arg1 arg2 arg3
arg4 arg5
 
`,
		cmd:  "fix:",
		args: "arg1 arg2 arg3",
	},
	{
		body: `
#syz  fix: arg1 arg2 arg3
arg4 arg5 
`,
		cmd:  "fix:",
		args: "arg1 arg2 arg3",
	},
}

type ParseTest struct {
	email string
	res   Email
}

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
			BugID:     "4564456",
			MessageID: "<123>",
			Link:      "https://groups.google.com/d/msgid/syzkaller/abcdef@google.com",
			Subject:   "test subject",
			From:      "\"Bob\" <bob@example.com>",
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
			Patch:       "",
			Command:     "fix:",
			CommandArgs: "arg1 arg2 arg3",
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
			BugID:     "4564456",
			MessageID: "<123>",
			Subject:   "test subject",
			From:      "\"syzbot\" <foo+4564456@bar.com>",
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
			Subject:   "test subject",
			From:      "\"Bob\" <bob@example.com>",
			Cc:        []string{"alice@example.com", "bob@example.com", "bot@example.com"},
			Body: `#syz  invalid   	 
text body
second line
last line`,
			Patch:       "",
			Command:     "invalid",
			CommandArgs: "",
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
			Subject:   "test subject",
			From:      "\"Bob\" <bob@example.com>",
			Cc:        []string{"alice@example.com", "bob@example.com", "bot@example.com"},
			Body: `text body
second line
last line
#syz command`,
			Patch:       "",
			Command:     "command",
			CommandArgs: "",
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
			Subject:   "test subject",
			From:      "\"Bob\" <bob@example.com>",
			Cc:        []string{"bob@example.com", "bot@example.com"},
			Body: `body text
>#syz test
`,
			Patch: `--- a/kernel/kcov.c
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
			Command:     "",
			CommandArgs: "",
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
			Subject:   "test subject",
			From:      "\"Bob\" <bob@example.com>",
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
			Patch: `--- a/fs/stat.c
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
			Command:     "test",
			CommandArgs: "",
		}},
}
