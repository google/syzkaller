// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package email

import (
	"fmt"
	"testing"
)

func TestFormReply(t *testing.T) {
	for i, test := range formReplyTests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			result := FormReply(test.email, test.reply)
			if test.result != result {
				t.Logf("expect:\n%s", test.result)
				t.Logf("got:\n%s", result)
				t.Fail()
			}
		})
	}
}

var formReplyTests = []struct {
	email  string
	reply  string
	result string
}{
	{
		email: `line1
line2
#syz foo
line3
`,
		reply: "this is reply",
		result: `> line1
> line2
> #syz foo

this is reply

> line3
`,
	},
	{
		email: `
#syz-fix
line2
`,
		reply: "this is reply",
		result: `>
> #syz-fix

this is reply

> line2
`,
	},
	{
		email: `
#syz: fix
line2
`,
		reply: "this is reply",
		result: `>
> #syz: fix

this is reply

> line2
`,
	},
	{
		email: `> line1
> line2
#syz foo
line3
`,
		reply: "this is reply\n",
		result: `>> line1
>> line2
> #syz foo

this is reply

> line3
`,
	},
	{
		email: `line1
line2
#syz foo`,
		reply: "this is reply 1\nthis is reply 2",
		result: `> line1
> line2
> #syz foo

this is reply 1
this is reply 2

`,
	},
	{
		email: `line1
line2
`,
		reply: "this is reply",
		result: `> line1
> line2

this is reply

`,
	},
}
