// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include "types.h"

enum {
	NLA_UNSPEC,
	NLA_U8,
	NLA_U16,
	NLA_U32,
	NLA_U64,
	NLA_STRING,
	NLA_FLAG,
	NLA_MSECS,
	NLA_NESTED,
	NLA_NESTED_ARRAY,
	NLA_NUL_STRING,
	NLA_BINARY,
	NLA_S8,
	NLA_S16,
	NLA_S32,
	NLA_S64,
	NLA_BITFIELD32,
	NLA_REJECT,
	NLA_BE16,
	NLA_BE32,
	NLA_SINT,
	NLA_UINT,
	__NLA_TYPE_MAX,
};

struct nla_policy {
	u8		type;
	u8		validation_type;
	u16		len;
	union {
		const u32 bitfield32_valid;
		const u32 mask;
		const struct nla_policy *nested_policy;
		struct { s16 min, max; };
	};
};

#define NLA_POLICY_NESTED(policy) { .type = NLA_NESTED, .nested_policy = policy, .len = sizeof(policy)/sizeof(policy[0]) }

#define GENL_ADMIN_PERM 0x01
#define GENL_UNS_ADMIN_PERM 0x10

struct genl_ops {
	u8				cmd;
	u8				flags;
	const struct nla_policy*	policy;
	void				(*doit)(void);
	void				(*dumpit)(void);
};

struct genl_split_ops {
	u8			cmd;
	u8			flags;
	const struct nla_policy *policy;
	union {
		struct {
			void (*pre_doit)(void);
			void (*doit)(void);
			void (*post_doit)(void);
		};
		struct {
			void (*start)(void);
			void (*dumpit)(void);
			void (*done)(void);
		};
	};
};

struct genl_small_ops {};

struct genl_family {
	char				name[64];
	u8				n_ops;
	u8				n_small_ops;
	u8				n_split_ops;
	const struct nla_policy* 	policy;
	const struct genl_ops*		ops;
	const struct genl_small_ops*	mall_ops;
	const struct genl_split_ops*	split_ops;
};
