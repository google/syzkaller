
// syz-minconfig is a tool for manual checking of config minimization functionality in pkg/kconfig/minimize.go.
// Example use:
//
//	$ go run tools/syz-minconfig/minconfig.go -sourcedir /src/linux -configs CAIF_NETDEV,CAIF_USB \
//		-base dashboard/config/linux/upstream-kasan-base.config \
//		-full dashboard/config/linux/upstream-kasan.config \
package main

import (
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/VerditeLabs/syzkaller/pkg/debugtracer"
	"github.com/VerditeLabs/syzkaller/pkg/kconfig"
	"github.com/VerditeLabs/syzkaller/pkg/tool"
	"github.com/VerditeLabs/syzkaller/sys/targets"
)

func main() {
	var (
		flagSourceDir = flag.String("sourcedir", "", "kernel sources dir")
		flagBase      = flag.String("base", "", "baseline config")
		flagFull      = flag.String("full", "", "full config")
		flagConfigs   = flag.String("configs", "", "comma-separated list of configs for the crash predicate")
		flagArch      = flag.String("arch", "amd64", "kernel arch (always amd64)")
	)
	flag.Parse()
	kconf, err := kconfig.Parse(targets.Get("linux", *flagArch), filepath.Join(*flagSourceDir, "Kconfig"))
	if err != nil {
		tool.Fail(err)
	}
	base, err := kconfig.ParseConfig(*flagBase)
	if err != nil {
		tool.Fail(err)
	}
	full, err := kconfig.ParseConfig(*flagFull)
	if err != nil {
		tool.Fail(err)
	}
	pred := func(candidate *kconfig.ConfigFile) (bool, error) {
		for _, cfg := range strings.Split(*flagConfigs, ",") {
			if candidate.Value(cfg) == kconfig.No {
				return false, nil
			}
		}
		return true, nil
	}
	gt := &debugtracer.GenericTracer{
		TraceWriter: os.Stdout,
	}
	res, err := kconf.Minimize(base, full, pred, 0, gt)
	if err != nil {
		tool.Fail(err)
	}
	os.Stdout.Write(res.Serialize())
}
