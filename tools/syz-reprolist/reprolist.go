// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
)

var (
	flagDashboard    = flag.String("dashboard", "https://syzkaller.appspot.com", "dashboard address")
	flagAPIClient    = flag.String("client", "", "api client")
	flagAPIKey       = flag.String("key", "", "api key")
	flagOutputDir    = flag.String("output", "repros", "output dir")
	flagSyzkallerDir = flag.String("syzkaller", ".", "syzkaller dir")
	flagOS           = flag.String("os", runtime.GOOS, "target OS")
)

func main() {
	flag.Parse()
	if *flagAPIClient == "" || *flagAPIKey == "" {
		log.Fatalf("api client and key are required")
	}
	if err := os.MkdirAll(*flagOutputDir, 0755); err != nil {
		log.Fatalf("failed to create output dir: %v", err)
	}
	dash := dashapi.New(*flagAPIClient, *flagDashboard, *flagAPIKey)
	resp, err := dash.BugList()
	if err != nil {
		log.Fatalf("api call failed: %v", err)
	}
	log.Printf("loading %v bugs", len(resp.List))
	const P = 10
	idchan := make(chan string, 10*P)
	bugchan := make(chan *dashapi.LoadBugResp, 10*P)
	go func() {
		for _, id := range resp.List {
			if _, err := os.Stat(filepath.Join(*flagOutputDir, id+".c")); err == nil {
				log.Printf("%v: already present", id)
				continue
			}
			if _, err := os.Stat(filepath.Join(*flagOutputDir, id+".norepro")); err == nil {
				log.Printf("%v: no repro (cached)", id)
				continue
			}
			if _, err := os.Stat(filepath.Join(*flagOutputDir, id+".error")); err == nil {
				log.Printf("%v: error (cached)", id)
				continue
			}
			idchan <- id
		}
		close(idchan)
	}()
	var wg sync.WaitGroup
	wg.Add(P)
	for p := 0; p < P; p++ {
		go func() {
			defer wg.Done()
			for id := range idchan {
				resp, err := dash.LoadBug(id)
				if err != nil {
					log.Printf("%v: failed to load bug: %v", id, err)
					continue
				}
				if resp.ID == "" {
					continue
				}
				bugchan <- resp
			}
		}()
	}
	go func() {
		wg.Wait()
		close(bugchan)
	}()
	writeRepros(bugchan)
}

func writeRepros(bugchan chan *dashapi.LoadBugResp) {
	for bug := range bugchan {
		if len(bug.ReproSyz) == 0 {
			log.Printf("%v: %v: no repro", bug.ID, bug.Status)
			file := filepath.Join(*flagOutputDir, bug.ID+".norepro")
			if err := ioutil.WriteFile(file, nil, 0644); err != nil {
				log.Fatalf("failed to write file: %v", err)
			}
			continue
		}
		if len(bug.ReproC) == 0 {
			log.Printf("%v: %v: syz repro on %v", bug.ID, bug.Status, bug.SyzkallerCommit)
			if err := createCRepro(bug); err != nil {
				log.Print(err)
				errText := []byte(err.Error())
				file := filepath.Join(*flagOutputDir, bug.ID+".error")
				if err := ioutil.WriteFile(file, errText, 0644); err != nil {
					log.Fatalf("failed to write file: %v", err)
				}
				continue
			}
		}
		log.Printf("%v: %v: C repro", bug.ID, bug.Status)
		arch := ""
		if bug.Arch != "" && bug.Arch != "amd64" {
			arch = fmt.Sprintf(" arch:%v", bug.Arch)
		}
		repro := []byte(fmt.Sprintf("// %v\n// %v/bug?id=%v\n// status:%v%v\n",
			bug.Title, *flagDashboard, bug.ID, bug.Status, arch))
		repro = append(repro, bug.ReproC...)
		file := filepath.Join(*flagOutputDir, bug.ID+".c")
		if err := ioutil.WriteFile(file, repro, 0644); err != nil {
			log.Fatalf("failed to write file: %v", err)
		}
	}
}

func createCRepro(bug *dashapi.LoadBugResp) error {
	opts, err := csource.DeserializeOptions(bug.ReproOpts)
	if err != nil {
		return fmt.Errorf("failed to deserialize opts: %v", err)
	}
	file := filepath.Join(*flagOutputDir, bug.ID+".syz")
	if err := ioutil.WriteFile(file, bug.ReproSyz, 0644); err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}
	repo := vcs.NewSyzkallerRepo(*flagSyzkallerDir)
	if _, err := repo.SwitchCommit(bug.SyzkallerCommit); err != nil {
		return fmt.Errorf("failed to checkout commit %v: %v", bug.SyzkallerCommit, err)
	}
	if _, err := osutil.RunCmd(time.Hour, *flagSyzkallerDir, "make", "prog2c"); err != nil {
		return err
	}
	bin := filepath.Join(*flagSyzkallerDir, "bin", "syz-prog2c")
	args := createProg2CArgs(bug, opts, file)
	output, err := osutil.RunCmd(time.Hour, "", bin, args...)
	if err != nil {
		return err
	}
	bug.ReproC = output
	return err
}

func createProg2CArgs(bug *dashapi.LoadBugResp, opts csource.Options, file string) []string {
	haveEnableFlag := containsCommit("dfd609eca1871f01757d6b04b19fc273c87c14e5")
	haveRepeatFlag := containsCommit("b25fc7b83119e8dca728a199fd92e24dd4c33fa4")
	haveCgroupFlag := containsCommit("9753d3be5e6c79e271ed128795039f161ee339b7")
	haveWaitRepeatFlag := containsCommit("c99b02d2248fbdcd6f44037326b16c928f4423f1")
	haveWaitRepeatRemoved := containsCommit("9fe4bdc5f1037a409e82299f36117030114c7b94")
	haveCloseFDs := containsCommit("5c51045d28eb1ad9465a51487d436133ce7b98d2")
	haveOSFlag := containsCommit("aa2533b98d21ebcad5777310215159127bfe3573")
	args := []string{
		"-prog", file,
		"-sandbox", opts.Sandbox,
		fmt.Sprintf("-segv=%v", opts.HandleSegv),
		fmt.Sprintf("-collide=%v", opts.Collide),
		fmt.Sprintf("-threaded=%v", opts.Threaded),
	}
	if haveOSFlag {
		args = append(args, "-os", *flagOS)
	}
	if bug.Arch != "" && bug.Arch != "amd64" {
		args = append(args, "-arch", bug.Arch)
	}
	if opts.Fault {
		args = append(args, []string{
			fmt.Sprintf("-fault_call=%v", opts.FaultCall),
			fmt.Sprintf("-fault_nth=%v", opts.FaultNth),
		}...)
	}
	if opts.Repeat {
		if haveRepeatFlag {
			args = append(args, fmt.Sprintf("-repeat=%v", opts.RepeatTimes))
		} else {
			args = append(args, "-repeat")
		}
	}
	if opts.Procs > 0 {
		args = append(args, fmt.Sprintf("-procs=%v", opts.Procs))
	}
	if opts.UseTmpDir {
		args = append(args, "-tmpdir")
	}
	if opts.Leak {
		args = append(args, "-leak")
	}
	var enable, flags []string
	if opts.NetInjection {
		enable = append(enable, "tun")
		flags = append(flags, "-tun")
	}
	if opts.NetDevices {
		enable = append(enable, "net_dev")
		flags = append(flags, "-netdev")
	}
	if opts.NetReset {
		enable = append(enable, "net_reset")
		flags = append(flags, "-resetnet")
	}
	if opts.Cgroups {
		enable = append(enable, "cgroups")
		if haveCgroupFlag {
			flags = append(flags, "-cgroups")
			if haveWaitRepeatFlag && !haveWaitRepeatRemoved {
				flags = append(flags, "-waitrepeat")
			}
		}
	}
	if opts.BinfmtMisc {
		enable = append(enable, "binfmt_misc")
	}
	if opts.CloseFDs && haveCloseFDs {
		enable = append(enable, "close_fds")
	}
	if opts.DevlinkPCI {
		enable = append(enable, "devlink_pci")
		flags = append(flags, "-devlinkpci")
	}
	if opts.VhciInjection {
		enable = append(enable, "vhci")
		flags = append(flags, "-vhci")
	}
	if !haveEnableFlag {
		args = append(args, flags...)
	} else if len(enable) != 0 {
		args = append(args, "-enable", strings.Join(enable, ","))
	}
	return args
}

func containsCommit(hash string) bool {
	_, err := osutil.RunCmd(time.Hour, *flagSyzkallerDir, "git", "merge-base", "--is-ancestor", hash, "HEAD")
	return err == nil
}
