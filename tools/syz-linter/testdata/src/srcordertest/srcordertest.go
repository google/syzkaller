// Comment in the beginning of the file.  // want "One or more declarations need to be reordered to provide natural reading order"

package testdata

import (
	"context"
)

// helper shuold be declared after foo.
func helper() {  // want "Move helper after foo \\(:13\\) b/c it's used in the body"
}

func (x *X) foo() {  // want "Move foo after X \\(:36\\) b/c uses type in the signature"
	helper()
}

// bar and foo shouldn't be reordered (methods of the same type).
func (x *X) bar(arg *Arg) *Ret {  // want "Move bar after Ret \\(:45\\) b/c uses type in the signature"
	x.foo()
	return nil
}

// Floating comment.

// This shuold be moved after X.
type Inner struct {  // want "Move Inner after X \\(:36\\) b/c it's a field type"
	x int
}

type Unrelated struct {}

// This should not be moved after X as used as embed field.
type Common struct {}

// X/Arg/Ret should move before bar that uses them in the signature.
type X struct {
	Common
	inner Inner
	Unrelated int // this does not use the Unrelated struct type
}

// Comment on the type.
type Arg struct{}

type Ret int // comment after the type

// This does not use the Context type from this package.
func usesContext(ctx context.Context) {
	c := &Context{}
	_ = c
}

type Context struct {
	x int
}

func (ctx *Context) foo() {}  // want "Move foo after useFoo \\(:59\\) b/c it's used in the body"

func useFoo(ctx *Context) {
	ctx.foo()
}

// Recursive functions shouldn't be reordered.
func recursive1() {
	recursive2()
}

func recursive2() {
	recursive3()
}

func recursive3() {
	recursive1()
}

func bar() {}

// Comment in the end of the file.
