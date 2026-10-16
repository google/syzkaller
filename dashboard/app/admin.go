// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"runtime"
	"slices"
	"strconv"
	"time"

	db "google.golang.org/appengine/v2/datastore"
	"google.golang.org/appengine/v2/log"
	aemail "google.golang.org/appengine/v2/mail"
)

func handleInvalidateBisection(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	encodedKey := r.FormValue("key")
	if encodedKey == "" {
		return fmt.Errorf("mandatory parameter key is missing")
	}
	jobKey, err := db.DecodeKey(encodedKey)
	if err != nil {
		return fmt.Errorf("failed to decode job key %v: %w", encodedKey, err)
	}

	err = invalidateBisection(ctx, jobKey, r.FormValue("restart") == "1")
	if err != nil {
		return fmt.Errorf("failed to invalidate job %v: %w", jobKey, err)
	}

	// Sending back to bug page after successful invalidation.
	http.Redirect(w, r, r.Header.Get("Referer"), http.StatusFound)
	return nil
}

// dropNamespace drops all entities related to a single namespace.
// Use with care. There is no undo.
// This functionality is intentionally not connected to any handler.
// To use it, first make a backup of the db. Then, specify the target
// namespace in the ns variable, connect the function to a handler, invoke it
// and double check the output. Finally, set dryRun to false and invoke again.
func dropNamespace(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	ns := "non-existent"
	dryRun := true
	if !dryRun {
		log.Criticalf(ctx, "dropping namespace %v", ns)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "dropping namespace %v\n", ns)
	if err := dropNamespaceReportingState(ctx, w, ns, dryRun); err != nil {
		return err
	}
	type Entity struct {
		name  string
		child string
	}
	entities := []Entity{
		{textPatch, ""},
		{textReproC, ""},
		{textReproSyz, ""},
		{textKernelConfig, ""},
		{"Job", ""},
		{textLog, ""},
		{textError, ""},
		{textCrashLog, ""},
		{textCrashReport, ""},
		{"Build", ""},
		{"Manager", "ManagerStats"},
		{"Bug", "Crash"},
	}
	for _, entity := range entities {
		keys, err := db.NewQuery(entity.name).
			Filter("Namespace=", ns).
			KeysOnly().
			GetAll(ctx, nil)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "%v: %v\n", entity.name, len(keys))
		if entity.child != "" {
			var childKeys []*db.Key
			for _, key := range keys {
				keys1, err := db.NewQuery(entity.child).
					Ancestor(key).
					KeysOnly().
					GetAll(ctx, nil)
				if err != nil {
					return err
				}
				childKeys = append(childKeys, keys1...)
			}
			fmt.Fprintf(w, "  %v: %v\n", entity.child, len(childKeys))
			if err := dropEntities(ctx, childKeys, dryRun); err != nil {
				return err
			}
		}
		if err := dropEntities(ctx, keys, dryRun); err != nil {
			return err
		}
	}
	return nil
}

func dropNamespaceReportingState(ctx context.Context, w http.ResponseWriter, ns string, dryRun bool) error {
	tx := func(ctx context.Context) error {
		state, err := loadReportingState(ctx)
		if err != nil {
			return err
		}
		newState := new(ReportingState)
		for _, ent := range state.Entries {
			if ent.Namespace != ns {
				newState.Entries = append(newState.Entries, ent)
			}
		}
		if !dryRun {
			if err := saveReportingState(ctx, newState); err != nil {
				return err
			}
		}
		fmt.Fprintf(w, "ReportingState: %v\n", len(state.Entries)-len(newState.Entries))
		return nil
	}
	return runInTransaction(ctx, tx, nil)
}

func dropEntities(ctx context.Context, keys []*db.Key, dryRun bool) error {
	if dryRun {
		return nil
	}
	for len(keys) != 0 {
		batch := min(len(keys), 100)
		if err := db.DeleteMulti(ctx, keys[:batch]); err != nil {
			return err
		}
		keys = keys[batch:]
	}
	return nil
}

func restartFailedBisections(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if accessLevel(ctx, r) != AccessAdmin {
		return fmt.Errorf("admin only")
	}
	ns := r.FormValue("ns")
	if ns == "" {
		return fmt.Errorf("no ns parameter")
	}
	var jobs []*Job
	var jobKeys []*db.Key
	jobKeys, err := db.NewQuery("Job").
		Filter("Finished>", time.Time{}).
		GetAll(ctx, &jobs)
	if err != nil {
		return fmt.Errorf("failed to query jobs: %w", err)
	}
	toReset := []*db.Key{}
	for i, job := range jobs {
		if job.Namespace != ns {
			continue
		}
		if job.Type != JobBisectCause && job.Type != JobBisectFix {
			continue
		}
		if job.Error == 0 {
			continue
		}
		errorTextBytes, _, err := getText(ctx, textError, job.Error)
		if err != nil {
			return fmt.Errorf("failed to query error text: %w", err)
		}
		fmt.Fprintf(w, "job type %v, ns %s, finished at %s, error:%s\n========\n",
			job.Type, job.Namespace, job.Finished, string(errorTextBytes))
		toReset = append(toReset, jobKeys[i])
	}
	if r.FormValue("apply") != "yes" {
		return nil
	}
	for idx, jobKey := range toReset {
		err = invalidateBisection(ctx, jobKey, true)
		if err != nil {
			fmt.Fprintf(w, "job %v update failed: %s", idx, err)
		}
	}

	fmt.Fprintf(w, "Done!\n")
	return nil
}

// updateBugReporting adds missing reporting stages to bugs in a single namespace.
// Use with care. There is no undo.
// This can be used to migrate datastore to a new config with more reporting stages.
// This functionality is intentionally not connected to any handler.
// Before invoking it is recommended to stop all connected instances just in case.
func updateBugReporting(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if accessLevel(ctx, r) != AccessAdmin {
		return fmt.Errorf("admin only")
	}
	ns := r.FormValue("ns")
	if ns == "" {
		return fmt.Errorf("no ns parameter")
	}
	var bugs []*Bug
	keys, err := db.NewQuery("Bug").
		Filter("Namespace=", ns).
		GetAll(ctx, &bugs)
	if err != nil {
		return err
	}
	log.Warningf(ctx, "fetched %v bugs for namespce %v", len(bugs), ns)
	cfg := getNsConfig(ctx, ns)
	var update []*db.Key
	for i, bug := range bugs {
		if len(bug.Reporting) >= len(cfg.Reporting) {
			continue
		}
		update = append(update, keys[i])
	}
	return updateBatch(ctx, update, func(_ *db.Key, bug *Bug) error {
		return bug.updateReportings(ctx, cfg, timeNow(ctx))
	})
}

// updateCrashPriorities regenerates priorities for crashes.
// This has become necessary after the "dashboard: support per-Manager priority" commit.
// For now, the method only considers the crashes referenced from bug origin.
func updateCrashPriorities(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if accessLevel(ctx, r) != AccessAdmin {
		return fmt.Errorf("admin only")
	}
	ns := r.FormValue("ns")
	if ns == "" {
		return fmt.Errorf("no ns parameter")
	}
	bugsCount := 0
	bugPerKey := map[string]*Bug{}
	var crashKeys []*db.Key
	if err := foreachBug(ctx, func(query *db.Query) *db.Query {
		return query.Filter("Status=", BugStatusOpen).Filter("Namespace=", ns)
	}, func(bug *Bug, key *db.Key) error {
		bugsCount++
		// There'll be duplicate crash IDs.
		crashIDs := map[int64]struct{}{}
		for _, item := range bug.TreeTests.List {
			crashIDs[item.CrashID] = struct{}{}
		}
		for crashID := range crashIDs {
			crashKeys = append(crashKeys, db.NewKey(ctx, "Crash", "", crashID, key))
		}
		bugPerKey[key.String()] = bug
		return nil
	}); err != nil {
		return err
	}
	log.Warningf(ctx, "fetched %d bugs and %v crash keys to update", bugsCount, len(crashKeys))
	return updateBatch(ctx, crashKeys, func(key *db.Key, crash *Crash) error {
		bugKey := key.Parent()
		bug := bugPerKey[bugKey.String()]
		build, err := loadBuild(ctx, ns, crash.BuildID)
		if err != nil {
			return err
		}
		if build == nil {
			return fmt.Errorf("failed to load build %v", crash.BuildID)
		}
		crash.UpdateReportingPriority(ctx, build, bug)
		return nil
	})
}

// setMissingBugFields makes sure all Bug entity fields are present in the database.
// The problem is that, in Datastore, sorting/filtering on a field will only return entries
// where that field is present.
func setMissingBugFields(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if accessLevel(ctx, r) != AccessAdmin {
		return fmt.Errorf("admin only")
	}
	var keys []*db.Key
	// Query everything.
	err := foreachBug(ctx, nil, func(bug *Bug, key *db.Key) error {
		keys = append(keys, key)
		return nil
	})
	if err != nil {
		return err
	}
	log.Warningf(ctx, "fetched %v bugs for update", len(keys))
	// Save everything unchanged.
	return updateBatch(ctx, keys, func(_ *db.Key, bug *Bug) error { return nil })
}

// adminSendEmail can be used to send an arbitrary message from the bot.
func adminSendEmail(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if accessLevel(ctx, r) != AccessAdmin {
		return fmt.Errorf("admin only")
	}
	msg := &aemail.Message{
		Sender: r.FormValue("from"),
		To:     []string{r.FormValue("to")},
		Body:   r.FormValue("body"),
	}
	return sendEmail(ctx, msg)
}

func updateHeadReproLevel(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if accessLevel(ctx, r) != AccessAdmin {
		return fmt.Errorf("admin only")
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	var keys []*db.Key
	type reproState struct {
		hasC   bool
		hasSyz bool
	}
	newLevels := map[string]reproState{}
	if err := foreachBug(ctx, func(query *db.Query) *db.Query {
		return query.Filter("Status=", BugStatusOpen)
	}, func(bug *Bug, key *db.Key) error {
		if len(bug.Commits) > 0 {
			return nil
		}
		actualC := false
		actualSyz := false
		reproCrashes, _, err := queryCrashesForBug(ctx, key, 2)
		if err != nil {
			return fmt.Errorf("failed to fetch crashes with repro: %w", err)
		}
		for _, crash := range reproCrashes {
			if crash.ReproIsRevoked {
				continue
			}
			if crash.ReproC > 0 {
				actualC = true
			}
			if crash.ReproSyz > 0 {
				actualSyz = true
			}
		}
		dbHasC := bug.HeadHasCRepro
		dbHasSyz := bug.HeadHasSyzRepro
		mismatch := (actualC != dbHasC) || (actualSyz != dbHasSyz)
		if mismatch {
			fmt.Fprintf(w, "%v: HeadReproLevel mismatch, actual C/Syz=%t/%t, db C/Syz=%t/%t\n",
				bugLink(key.StringID()), actualC, actualSyz, dbHasC, dbHasSyz)
			newLevels[key.StringID()] = reproState{hasC: actualC, hasSyz: actualSyz}
			keys = append(keys, key)
		}
		return nil
	}); err != nil {
		return err
	}
	return updateBatch(ctx, keys, func(key *db.Key, bug *Bug) error {
		state, ok := newLevels[key.StringID()]
		if !ok {
			return fmt.Errorf("fetched unknown bug %v", key.StringID())
		}
		bug.SetHeadReproLevel(state.hasC, state.hasSyz)
		return nil
	})
}

func updateBatch[T any](ctx context.Context, keys []*db.Key, transform func(key *db.Key, item *T) error) error {
	for len(keys) != 0 {
		batchSize := min(len(keys), 20)
		batchKeys := keys[:batchSize]
		keys = keys[batchSize:]

		tx := func(ctx context.Context) error {
			items := make([]*T, len(batchKeys))
			if err := db.GetMulti(ctx, batchKeys, items); err != nil {
				return err
			}
			for i, item := range items {
				if err := transform(batchKeys[i], item); err != nil {
					return err
				}
			}
			_, err := db.PutMulti(ctx, batchKeys, items)
			return err
		}
		if err := runInTransaction(ctx, tx, &db.TransactionOptions{XG: true}); err != nil {
			return err
		}
		log.Warningf(ctx, "updated %v bugs", len(batchKeys))
	}
	return nil
}

func forceCommitInfoUpdate(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	// Read an optional "?limit=X" parameter from the URL.
	limit := 0
	if limitStr := r.FormValue("limit"); limitStr != "" {
		parsed, err := strconv.Atoi(limitStr)
		if err != nil {
			return fmt.Errorf("invalid limit parameter %q: %w", limitStr, err)
		}
		if parsed <= 0 {
			return fmt.Errorf("limit parameter must be positive")
		}
		limit = parsed
	}

	var keys []*db.Key
	err := foreachBug(ctx, nil, func(bug *Bug, key *db.Key) error {
		if limit > 0 && len(keys) >= limit {
			return nil // Stop accumulating if we hit our requested limit.
		}
		if len(bug.Commits) > 0 && !bug.NeedCommitInfo {
			keys = append(keys, key)
		}
		return nil
	})
	if err != nil {
		return err
	}

	log.Warningf(ctx, "fetched %v bugs for commit info update", len(keys))
	return updateBatch(ctx, keys, func(_ *db.Key, bug *Bug) error {
		bug.NeedCommitInfo = true
		return nil
	})
}

var (
	gceE2Standard2  = BuildEnv{VMType: "gce", MachineType: "e2-standard-2"}
	gceN2DStandard2 = BuildEnv{VMType: "gce", MachineType: "n2d-standard-2"}
	gceN2Standard2  = BuildEnv{VMType: "gce", MachineType: "n2-standard-2"}
	gceC4AStandard2 = BuildEnv{VMType: "gce", MachineType: "c4a-standard-2"}

	// nolint: lll
	managerBuildEnv = map[string]BuildEnv{
		"ci-upstream-kasan-gce":                 gceE2Standard2,
		"ci-upstream-kasan-gce-root":            gceN2DStandard2,
		"ci-upstream-kasan-badwrites-root":      gceN2DStandard2,
		"ci-upstream-kasan-gce-selinux-root":    gceN2Standard2,
		"ci-upstream-kasan-gce-smack-root":      gceE2Standard2,
		"ci-upstream-linux-next-kasan-gce-root": gceE2Standard2,
		"ci-upstream-bpf-kasan-gce":             gceE2Standard2,
		"ci-upstream-bpf-next-kasan-gce":        gceE2Standard2,
		"ci-upstream-net-this-kasan-gce":        gceE2Standard2,
		"ci-upstream-net-kasan-gce":             gceE2Standard2,
		"ci-upstream-kasan-gce-386":             gceE2Standard2,
		"ci-upstream-gce-leak":                  gceE2Standard2,
		"ci-upstream-kmsan-gce-root":            gceE2Standard2,
		"ci-upstream-kmsan-gce-386-root":        gceE2Standard2,
		"ci-upstream-gce-arm64":                 gceC4AStandard2,
		"ci-upstream-rust-kasan-gce":            gceE2Standard2,

		"ci2-upstream-usb":       gceE2Standard2,
		"ci2-upstream-kcsan-gce": gceE2Standard2,
		"ci2-upstream-fs":        gceE2Standard2,

		"ci-qemu-upstream": {
			VMType:   "qemu",
			QemuArgs: "-enable-kvm -machine q35,nvdimm=on,accel=kvm,kernel-irqchip=split -cpu max,migratable=off -smp 4,maxcpus=8,cores=2,threads=2,sockets=2 -device ioh3420,id=pcie.1,chassis=1 -device intel-iommu,intremap=on,device-iotlb=on -vga virtio -usb -usbdevice tablet -m 4G,slots=4,maxmem=16G -object memory-backend-file,id=pmem1,share=off,mem-path=/dev/zero,size=64M -device nvdimm,id=nvdimm1,memdev=pmem1 -net nic,model=e1000e -fdb {{TEMPLATE}}/fd -cdrom {{TEMPLATE}}/cdrom -virtfs local,path={{TEMPLATE}}/virtfs,mount_tag=syz,security_model=mapped-xattr,id=syz",
		},
		"ci-qemu-upstream-386": {
			VMType:   "qemu",
			QemuArgs: "-enable-kvm -machine q35,nvdimm=on,accel=kvm,kernel-irqchip=split -cpu max,migratable=off -smp 4,maxcpus=8,cores=2,threads=2,sockets=2 -device ioh3420,id=pcie.1,chassis=1 -device intel-iommu,intremap=on,device-iotlb=on -vga std -usb -usbdevice tablet -m 2G,slots=4,maxmem=16G -object memory-backend-file,id=pmem1,share=off,mem-path=/dev/zero,size=64M -device nvdimm,id=nvdimm1,memdev=pmem1 -net nic,model=e1000e -fdb {{TEMPLATE}}/fd -cdrom {{TEMPLATE}}/cdrom -virtfs local,path={{TEMPLATE}}/virtfs,mount_tag=syz,security_model=mapped-xattr,id=syz",
		},
		"ci-qemu-gce-upstream-auto": gceE2Standard2,

		"ci-qemu2-arm32": {
			VMType:   "qemu",
			QemuArgs: "-machine vexpress-a15 -cpu cortex-a15 -dtb /syzkaller/shared/dtb/vexpress-v2p-ca15-tc1.dtb -accel tcg,thread=multi",
		},
		"ci-qemu2-arm64": {
			VMType:   "qemu",
			QemuArgs: "-machine virt,virtualization=on,graphics=on,usb=on -cpu cortex-a57 -accel tcg,thread=multi",
		},
		"ci-qemu2-arm64-compat": {
			VMType:   "qemu",
			QemuArgs: "-machine virt,virtualization=on,graphics=on,usb=on -cpu cortex-a57 -accel tcg,thread=multi",
		},
		"ci-qemu2-arm64-mte": {
			VMType:   "qemu",
			QemuArgs: "-machine virt,virtualization=on,mte=on,graphics=on,usb=on -cpu max -accel tcg,thread=multi",
		},
		"ci-qemu2-riscv64": {
			VMType: "qemu",
		},
		"ci-qemu-native-arm64-kvm": {
			VMType:   "qemu",
			QemuArgs: "-machine virt,virtualization=on -cpu max,sve=off,pauth=off -machine gic-version=max -accel tcg,thread=multi",
		},
		"ci-snapshot-upstream-root": {
			VMType:   "qemu",
			QemuArgs: "-enable-kvm -machine q35,nvdimm=on,accel=kvm,kernel-irqchip=split -m 1536M,slots=4,maxmem=16G -device ioh3420,id=pcie.1,chassis=1 -device intel-iommu,intremap=on,device-iotlb=on -vga virtio -usb -usbdevice tablet -object memory-backend-file,id=pmem1,share=off,mem-path=/dev/zero,size=64M -device nvdimm,id=nvdimm1,memdev=pmem1 -net nic,model=e1000e -cdrom {{TEMPLATE}}/cdrom -virtfs local,path={{TEMPLATE}}/virtfs,mount_tag=syz,security_model=mapped-xattr,id=syz,readonly=on",
		},
	}
)

func populateBuildEnv(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if accessLevel(ctx, r) != AccessAdmin {
		return fmt.Errorf("admin only")
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	ns := r.FormValue("ns")
	buildKeys := make(map[string]*db.Key)
	if err := foreachBug(ctx, func(query *db.Query) *db.Query {
		query = query.Filter("Status=", BugStatusOpen)
		if ns != "" {
			query = query.Filter("Namespace=", ns)
		}
		return query
	}, func(bug *Bug, bugKey *db.Key) error {
		crashes, _, err := queryCrashesForBug(ctx, bugKey, 3)
		if err != nil {
			return err
		}
		for _, crash := range crashes {
			bKey := buildKey(ctx, bug.Namespace, crash.BuildID)
			buildKeys[bKey.String()] = bKey
		}
		return nil
	}); err != nil {
		return err
	}
	return updateBatch(ctx, slices.Collect(maps.Values(buildKeys)), func(_ *db.Key, build *Build) error {
		if build.BuildEnv != (BuildEnv{}) {
			return nil
		}
		activeMgr, _ := activeManager(ctx, build.Manager, build.Namespace)
		if env, ok := managerBuildEnv[activeMgr]; ok {
			build.BuildEnv = env
		} else {
			fmt.Fprintf(w, "skipping build %v/%v: unknown manager %q (active %q)\n",
				build.Namespace, build.ID, build.Manager, activeMgr)
		}
		return nil
	})
}

func init() {
	// Prevent warnings about dead code.
	runtime.KeepAlive(dropNamespace)
	runtime.KeepAlive(dropEntities)
	runtime.KeepAlive(adminSendEmail)
	runtime.KeepAlive(updateHeadReproLevel)
	runtime.KeepAlive(updateCrashPriorities)
}
