// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Description of some hypothetic netlink family.

enum netlink_foo_cmds {
  NETLINK_FOO_CMD_FOO,
  NETLINK_FOO_CMD_BAR,
};

enum netlink_foo_attrs {
  NETLINK_FOO_ATTR1,
  NETLINK_FOO_ATTR2,
  NETLINK_FOO_ATTR3 = NETLINK_FOO_ATTR2 + 3,  // make them non-dense
  NETLINK_FOO_ATTR4,
  NETLINK_FOO_ATTR5,
  NETLINK_FOO_ATTR6,
  NETLINK_FOO_ATTR7,
};

struct netlink_foo_struct1 {
  int a, b, c;
};

typedef struct {
  double a, b, c;
} netlink_foo_struct2;
