// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include "include/netlink.h"
#include "include/uapi/netlink_family.h"

// These consts are defined not in uapi .h, so the descriptions should contain
// values for them rather than includes.
enum netlink_foo_nested_attrs {
  NETLINK_FOO_NESTED_ATTR1,
  NETLINK_FOO_NESTED_ATTR2,
};

static netlink_foo_struct2 var;

const struct nla_policy foo_genl_nested_policy[] = {
	[NETLINK_FOO_NESTED_ATTR1]	= { .type = NLA_U32 },
	[NETLINK_FOO_NESTED_ATTR2]	= { .type = NLA_U32 },
};

const struct nla_policy foo_genl_policy[] = {
	[NETLINK_FOO_ATTR1]	= { .type = NLA_U32 },
	[NETLINK_FOO_ATTR2]	= { .type = NLA_STRING, .len = 10 },
	[NETLINK_FOO_ATTR3]	= { .type = NLA_NESTED },
	[NETLINK_FOO_ATTR4]	= NLA_POLICY_NESTED(foo_genl_nested_policy),
	[NETLINK_FOO_ATTR5]	= { .len = sizeof(struct netlink_foo_struct1) },
	[NETLINK_FOO_ATTR6]	= { .len = sizeof(netlink_foo_struct2) * 10 },
	[NETLINK_FOO_ATTR7]	= { .len = sizeof(var) },
};

const struct nla_policy foo_dump_genl_policy[] = {
	[NETLINK_FOO_ATTR1]	= { .type = NLA_U32 },
};

const struct nla_policy genl_policy_reject_all[] = {
	{ .type = NLA_REJECT },
	{ .type = NLA_REJECT },
};

const struct nla_policy policy_forward_decl[10];

static void foo_cmd() {}
static void bar_cmd() {}

static const struct genl_ops foo_ops[] = {
	{
		.cmd = NETLINK_FOO_CMD_FOO,
		.flags = GENL_ADMIN_PERM,
		.doit = foo_cmd,
	},
	{
		.cmd = NETLINK_FOO_CMD_BAR,
		.flags = GENL_UNS_ADMIN_PERM,
		.doit = bar_cmd,
	},
	{
		.cmd = NETLINK_FOO_CMD_BAR,
		.flags = GENL_UNS_ADMIN_PERM,
		.dumpit = bar_cmd,
		.policy = foo_dump_genl_policy,
	},
};

static struct genl_family foo_family = {
	.ops = foo_ops,
	.n_ops = ARRAY_SIZE(foo_ops),
	.name = "foo family",
	.policy = foo_genl_policy,
};

enum {
	NETLINK_BAR_CMD_FOO,
};

static void bar_pre_doit() {}
static void bar_doit() {}
static void bar_post_doit() {}

static const struct genl_split_ops bar_ops[] = {
	{
		.cmd = NETLINK_BAR_CMD_FOO,
		.pre_doit = bar_pre_doit,
		.doit = bar_doit,
		.post_doit = bar_post_doit,
	},
};

struct genl_family bar_family = {
	.split_ops = bar_ops,
	.n_split_ops = ARRAY_SIZE(bar_ops),
	.name = "BAR",
	.policy = foo_genl_policy,
};

struct genl_family noops_family = {
	.name = "NOOPS",
};

enum netlink_nopolicy_cmds {
	NETLINK_NOPOLICY_CMD,
};

static const struct genl_ops nopolicy_ops[] = {
	{
		.cmd = NETLINK_NOPOLICY_CMD,
		.doit = foo_cmd,
	},
};

struct genl_family nopolicy_family = {
	.name = "nopolicy",
	.ops = nopolicy_ops,
	.n_ops = ARRAY_SIZE(nopolicy_ops),
};
