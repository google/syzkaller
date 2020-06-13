// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mab"
	"github.com/google/syzkaller/pkg/rpctype"
)

func (status *MABStatus) readMABStatus() rpctype.RPCMABStatus {
	fuzzerStatus := rpctype.RPCMABStatus{
		Round:        status.Round,
		Exp31Round:   status.Exp31Round,
		Reward:       status.Reward,
		CorpusReward: make(map[hash.Sig]mab.CorpusReward),
	}
	const batchSize = 100
	syncedCnt := 0
	synced := make([]int, batchSize)
	for pidx := range status.CorpusUpdate {
		// Avoid sending too much
		if syncedCnt >= batchSize {
			break
		}
		if pidx >= 0 && pidx < len(status.fuzzer.corpus) {
			p := status.fuzzer.corpus[pidx]
			sig := hash.Hash(p.Serialize())
			fuzzerStatus.CorpusReward[sig] = p.CorpusReward
			log.Logf(MABLogLevel, "MAB Corpus Sync Send %v: %+v\n", sig.String(), p.CorpusReward)
			synced[syncedCnt] = pidx
			syncedCnt++
		}
	}
	for i := 0; i < syncedCnt; i++ {
		spidx := synced[i]
		delete(status.CorpusUpdate, spidx)
	}
	log.Logf(MABLogLevel, "MAB Corpus Sync Pending: %v\n", len(status.CorpusUpdate))
	return fuzzerStatus
}

func (status *MABStatus) writeMABStatus(managerStatus rpctype.RPCMABStatus) {
	if status.Round < managerStatus.Round {
		status.Round = managerStatus.Round
		status.Exp31Round = managerStatus.Exp31Round
		status.BootstrapExp31()
		status.Reward = managerStatus.Reward
	}
	for sig, v := range managerStatus.CorpusReward {
		pidx := -1
		ok := false
		if pidx, ok = status.fuzzer.corpusHashes[sig]; ok && pidx >= 0 && pidx < len(status.fuzzer.corpus) {
			status.fuzzer.corpus[pidx].CorpusReward = v
			sig := hash.Hash(status.fuzzer.corpus[pidx].Serialize())
			log.Logf(MABLogLevel, "MAB Corpus Sync Receive %v: %+v\n", sig.String(), v)
		}
	}
}
