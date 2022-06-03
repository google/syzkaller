package report

import "path/filepath"

type kos struct {
	*config
}

func ctorKOS(cfg *config) (reporterImpl, []string, error) {
	ctx := &fuchsia{
		config: cfg,
	}
	if ctx.kernelObj != "" {
		ctx.obj = filepath.Join(ctx.kernelObj, ctx.target.KernelObject)
	}
	suppressions := []string{
		"fatal exception: process /tmp/syz-fuzzer", // OOM presumably
	}
	return ctx, suppressions, nil
}

func (k *kos) ContainsCrash(output []byte) bool {
	// TODO: implement logic to read kos kernel console output messages
	return false
}

func (k *kos) Parse(output []byte) *Report {
	// TODO: imeplement kos kernel console output parsing
	return nil

}

func (k *kos) Symbolize(rep *Report) error {
	// TODO: Implementation
	return nil
}
