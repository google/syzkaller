
package main

// The objective of this file is to collect config parts and routines useful for Linux bugs management,
// thus reducing the size of the dashboard config file.

// canBeVfsBug determines whether a bug could belong to the VFS subsystem itself.
func canBeVfsBug(bug *Bug) bool {
	for _, subsystem := range bug.LabelValues(SubsystemLabel) {
		// The "vfs" one is left for compatibility with the older matching code.
		if subsystem.Value == "vfs" || subsystem.Value == "fs" {
			return true
		}
	}
	return false
}
