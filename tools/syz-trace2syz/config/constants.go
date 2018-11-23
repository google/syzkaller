// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config

var (
	// Strace uses its own flag names. Map them to real ones
	Consts = map[string]string{
		"O_ASYNC":        "FASYNC", // O_ASYNC is used in libc headers
		"BUS":            "SIGBUS",
		"USR1":           "SIGUSR1",
		"ALRM":           "SIGALRM",
		"IO":             "SIGIO",
		"HUP":            "POLLHUP",
		"INT":            "SIGINT",
		"ILL":            "SIGILL",
		"SIGRT_2":        "SIGUSR1",
		"SIGRT_3":        "SIGUSR1",
		"SIGRT_4":        "SIGUSR1",
		"SIGRT_5":        "SIGUSR1",
		"SIGRT_6":        "SIGUSR1",
		"SIGRT_7":        "SIGUSR1",
		"SIGRT_8":        "SIGUSR1",
		"SIGRT_9":        "SIGUSR1",
		"SIGRT_10":       "SIGUSR1", // Map these rt signals to just one user signal.
		"SIGRT_11":       "SIGUSR1",
		"SIGRT_12":       "SIGUSR1",
		"SIGRT_13":       "SIGUSR1",
		"SIGRT_14":       "SIGUSR1",
		"SIGRT_15":       "SIGUSR1",
		"SIGRT_19":       "SIGUSR1",
		"IP_ORIGDSTADDR": "IP_RECVORIGDSTADDR",
		"SCHED_OTHER":    "SCHED_NORMAL",
	}
)
