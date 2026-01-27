// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#ifndef EXECUTOR_COMMON_H
#define EXECUTOR_COMMON_H

#include <stdio.h>
#include <string.h>

static void get_last_opt(const char* cmdline, const char* key, char* out, size_t out_len)
{
	char key_eq[128];
	snprintf(key_eq, sizeof(key_eq), "%s=", key);
	const char* val = NULL;
	for (const char* p = cmdline; (p = strstr(p, key_eq)); p += strlen(key_eq)) {
		if (p == cmdline || p[-1] == ' ' || p[-1] == '\t' || p[-1] == '\n')
			val = p + strlen(key_eq);
	}

	if (val) {
		size_t len = strcspn(val, " \t\n");
		if (len >= out_len)
			len = out_len - 1;
		memcpy(out, val, len);
		out[len] = 0;
	}
}

#endif // EXECUTOR_COMMON_H
