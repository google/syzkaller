// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/email/lore"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/controller"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSeriesProcessor(t *testing.T) {
	emails := []string{
		`Date: Sun, 7 May 2017 19:54:00 -0700
Message-ID: <123>
Subject: test subject
From: Bob <bob@example.com>
To: A <a@a.com>
Cc: B <b@b.com>, C <b@b.com>

first body`,
		`Date: Sun, 7 May 2017 19:55:00 -0700
Message-ID: <234>
Subject: test subject2
From: Bob <bob@example.com>
To: A <a@a.com>
Cc: D <d@d.com>

second body`,
	}
	bodies := []string{"first body", "second body"}

	sp := seriesProcessor{}
	for i, raw := range emails {
		body, err := sp.Process([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, []byte(bodies[i]), body)
	}
	assert.Equal(t, []string{
		"a@a.com", "b@b.com",
		"bob@example.com", "d@d.com",
	}, sp.Emails())
}

func TestHandleSeriesReportLevel(t *testing.T) {
	tests := []struct {
		name            string
		directList      string
		rawCc           []string
		ownEmail        bool
		wantDirect      bool
		wantReportLevel string
	}{
		{
			name:            "standard series",
			directList:      "direct@syzkaller.com",
			rawCc:           []string{"user@test.com"},
			ownEmail:        false,
			wantDirect:      false,
			wantReportLevel: "bugs",
		},
		{
			name:            "direct request series",
			directList:      "direct@syzkaller.com",
			rawCc:           []string{"user@test.com", "direct@syzkaller.com"},
			ownEmail:        false,
			wantDirect:      true,
			wantReportLevel: "all",
		},
		{
			name:            "own email series",
			directList:      "direct@syzkaller.com",
			rawCc:           []string{"user@test.com"},
			ownEmail:        true,
			wantDirect:      false,
			wantReportLevel: "none",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env, ctx := app.TestEnvironment(t)
			client := controller.TestServer(t, env)
			sessionRepo := db.NewSessionRepository(env.Spanner)

			sf := &SeriesFetcher{client: client}
			cfg := &app.AppConfig{
				DirectList: tt.directList,
			}
			msgID := "msg-" + tt.name
			series := &lore.Series{
				Subject:   "Subject " + tt.name,
				MessageID: msgID,
				Patches: []lore.Patch{
					{
						Email: &lore.Email{
							Email: &email.Email{
								MessageID: msgID,
								Author:    "author@test.com",
								RawCc:     tt.rawCc,
								OwnEmail:  tt.ownEmail,
							},
						},
					},
				},
			}
			idToReader := map[string]lore.EmailReader{
				msgID: {
					Read: func() ([]byte, error) {
						return []byte("patch content"), nil
					},
				},
			}

			err := sf.handleSeries(ctx, cfg, series, idToReader)
			require.NoError(t, err)

			dbSeries, err := db.NewSeriesRepository(env.Spanner).GetByExtID(ctx, msgID)
			require.NoError(t, err)
			require.NotNil(t, dbSeries)

			sessions, err := sessionRepo.ListForSeries(ctx, dbSeries)
			require.NoError(t, err)
			require.Len(t, sessions, 1)

			assert.Equal(t, tt.wantDirect, sessions[0].Direct.Bool)
			assert.Equal(t, tt.wantReportLevel, sessions[0].ReportLevel.StringVal)
		})
	}
}
