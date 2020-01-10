#!/bin/sh
# Copyright 2019 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# To use:
# - place this script to /usr/local/etc/rc.d/syz_ci
# - chmod a+x /usr/local/etc/rc.d/syz_ci
# - add the following to /etc/rc.conf (uncommented):
#
# syz_ci_enable="YES"
# syz_ci_chdir="/syzkaller"
# syz_ci_flags="-config config-freebsd.ci"
# syz_ci_log="/syzkaller/syz-ci.log"
# syz_ci_path="/syzkaller/syz-ci"
#
# Then syz-ci will start after boot, to manually start/stop:
# service syz_ci stop
# service syz_ci start

# PROVIDE: syz_ci
# REQUIRE: LOGIN

. /etc/rc.subr

command="${syz_ci_path}"
name="syz_ci"
pidfile="/var/run/${name}.pid"
rcvar="syz_ci_enable"
start_cmd="syz_ci_start"
stop_cmd="syz_ci_stop"

# syz-ci needs to be able to find the go executable.
PATH=${PATH}:/usr/local/bin

syz_ci_start()
{
	cd "${syz_ci_chdir}"
	daemon -f -o "${syz_ci_log}" -p ${pidfile} "${syz_ci_path}" ${syz_ci_flags}
}

syz_ci_stop()
{
	local _pid

	_pid=$(cat ${pidfile})
	kill -INT $_pid
	[ $? -eq 0 ] || return 1
	pwait -t 120s $_pid
}

load_rc_config $name
run_rc_command "$1"
