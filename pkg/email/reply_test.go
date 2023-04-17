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
	email  *Email
	reply  string
	result string
}{
	{
		email: &Email{
			Body: `line1
line2
#syz foo
line3
`},
		reply: "this is reply",
		result: `> line1
> line2
> #syz foo

this is reply

> line3
`,
	},
	{
		email: &Email{
			Body: `
#syz-fix
line2
`},
		reply: "this is reply",
		result: `>
> #syz-fix

this is reply

> line2
`,
	},
	{
		email: &Email{
			Body: `
#syz: fix
line2
`},
		reply: "this is reply",
		result: `>
> #syz: fix

this is reply

> line2
`,
	},
	{
		email: &Email{
			Body: `> line1
> line2
#syz foo
line3
`},
		reply: "this is reply\n",
		result: `>> line1
>> line2
> #syz foo

this is reply

> line3
`,
	},
	{
		email: &Email{
			Body: `line1
line2
#syz foo`},
		reply: "this is reply 1\nthis is reply 2",
		result: `> line1
> line2
> #syz foo

this is reply 1
this is reply 2

`,
	},
	{
		email: &Email{
			Body: `line1
line2
`},
		reply: "this is reply",
		result: `> line1
> line2

this is reply

`,
	},
	{
		email: &Email{
			Body: `line1
#syz foo
line2
#syz bar`,
			Commands: []*SingleCommand{
				{},
				{},
			},
		},
		reply: "this is reply 1\nthis is reply 2",
		result: `> line1
> #syz foo
> line2
> #syz bar

this is reply 1
this is reply 2

`,
	},
}
