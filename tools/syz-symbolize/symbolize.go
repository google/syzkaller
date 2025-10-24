
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/VerditeLabs/syzkaller/pkg/hash"
	"github.com/VerditeLabs/syzkaller/pkg/mgrconfig"
	"github.com/VerditeLabs/syzkaller/pkg/osutil"
	"github.com/VerditeLabs/syzkaller/pkg/report"
	"github.com/VerditeLabs/syzkaller/pkg/tool"
	"github.com/VerditeLabs/syzkaller/pkg/vcs"
)

var (
	flagOS        = flag.String("os", "linux", "target os (always linux)")
	flagArch      = flag.String("arch", "amd64", "target arch (always amd64)")
	flagKernelObj = flag.String("kernel_obj", ".", "path to kernel build/obj dir")
	flagKernelSrc = flag.String("kernel_src", "", "path to kernel sources (defaults to kernel_obj)")
	flagOutDir    = flag.String("outdir", "", "output directory")
	flagConfig    = flag.String("config", "", "optional configuration file")
)

func main() {
	flag.Parse()
	if len(flag.Args()) != 1 {
		fmt.Fprintf(os.Stderr, "usage: syz-symbolize [flags] kernel_log_file\n")
		flag.PrintDefaults()
		os.Exit(1)
	}
	var err error
	cfg := &mgrconfig.Config{}
	if *flagConfig != "" {
		cfg, err = mgrconfig.LoadPartialFile(*flagConfig)
	} else {
		cfg, err = mgrconfig.LoadPartialData([]byte(`{
			"kernel_obj": "` + *flagKernelObj + `",
			"kernel_src": "` + *flagKernelSrc + `",
			"target": "` + *flagOS + "/" + *flagArch + `"
		}`))
	}
	if err != nil {
		tool.Fail(err)
	}
	cfg.CompleteKernelDirs()
	reporter, err := report.NewReporter(cfg)
	if err != nil {
		tool.Failf("failed to create reporter: %v", err)
	}
	text, err := os.ReadFile(flag.Args()[0])
	if err != nil {
		tool.Failf("failed to open input file: %v", err)
	}
	reps := report.ParseAll(reporter, text)
	if len(reps) == 0 {
		rep := &report.Report{Report: text}
		if err := reporter.Symbolize(rep); err != nil {
			tool.Failf("failed to symbolize report: %v", err)
		}
		os.Stdout.Write(rep.Report)
		return
	}
	for _, rep := range reps {
		if *flagOutDir != "" {
			saveCrash(rep, *flagOutDir)
		}
		if err := reporter.Symbolize(rep); err != nil {
			fmt.Fprintf(os.Stderr, "failed to symbolize report: %v\n", err)
		}
		fmt.Printf("TITLE: %v\n", rep.Title)
		fmt.Printf("CORRUPTED: %v (%v)\n", rep.Corrupted, rep.CorruptedReason)
		fmt.Printf("SUPPRESSED: %v\n", rep.Suppressed)
		fmt.Printf("MAINTAINERS (TO): %v\n", rep.Recipients.GetEmails(vcs.To))
		fmt.Printf("MAINTAINERS (CC): %v\n", rep.Recipients.GetEmails(vcs.Cc))
		fmt.Printf("\n")
		os.Stdout.Write(rep.Report)
		fmt.Printf("\n\n")
	}
}

func saveCrash(rep *report.Report, path string) {
	sig := hash.Hash([]byte(rep.Title))
	id := sig.String()
	dir := filepath.Join(path, id)
	osutil.MkdirAll(dir)
	if err := osutil.WriteFile(filepath.Join(dir, "description"), []byte(rep.Title+"\n")); err != nil {
		tool.Failf("failed to write description: %v", err)
	}

	if err := osutil.WriteFile(filepath.Join(dir, "log"), rep.Output); err != nil {
		tool.Failf("failed to write log: %v", err)
	}

	if len(rep.Report) > 0 {
		if err := osutil.WriteFile(filepath.Join(dir, "report"), rep.Report); err != nil {
			tool.Failf("failed to write report: %v", err)
		}
	}
}
