// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package asset

import "github.com/google/syzkaller/sys/targets"

type Type string

// Asset types used throughout the system.
const (
	BootableDisk       Type = "bootable_disk"
	NonBootableDisk    Type = "non_bootable_disk"
	KernelObject       Type = "kernel_object"
	KernelImage        Type = "kernel_image"
	HTMLCoverageReport Type = "html_coverage_report"
)

func GetHumanReadableName(assetType Type, target *targets.Target) string {
	switch assetType {
	case BootableDisk:
		return "disk image"
	case NonBootableDisk:
		return "disk image (non-bootable)"
	case KernelImage:
		return "kernel image"
	case KernelObject:
		if target != nil && target.KernelObject != "" {
			return target.KernelObject
		}
		return "kernel object"
	case HTMLCoverageReport:
		return "coverage report (html)"
	default:
		panic("invalid asset type: " + assetType)
	}
}
