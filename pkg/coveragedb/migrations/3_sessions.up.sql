-- Copyright 2026 syzkaller project authors. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

CREATE TABLE sessions (
    session text,
    created timestamptz NOT NULL,
    PRIMARY KEY (session)
);
