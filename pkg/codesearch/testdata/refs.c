// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

int refs0()
{
	return 0;
}

void refs1()
{
}

void refs2(void (*)(), int)
{
}

void refs3()
{
	refs2(refs1, refs0());
	(void)refs2;
}

void long_func_with_ref()
{
	refs0();
	refs1();
	refs0();
	refs1();
	refs2(refs1, refs0());
	refs0();
	refs1();
	refs0();
	refs1();
}
