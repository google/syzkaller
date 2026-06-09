// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dashapi

import (
	"bytes"
	"testing"
)

func TestNewOpts(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
	}{
		{
			name: "no_options",
		},
		{
			name:      "custom_user_agent",
			userAgent: "Custom Agent/2.3",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := []DashboardOpts{}
			if test.userAgent != "" {
				opts = append(opts, UserAgent(test.userAgent))
			}
			dash, err := New("some_client", "some_addr", "some_key", opts...)
			if err != nil {
				t.Fatalf("call to New() returned unexpected error, got: %v, want: nil", err)
			}

			req, err := dash.ctor("GET", "http://www.example.com", bytes.NewBuffer([]byte("body")))
			if err != nil {
				t.Errorf("ctor() returned unexpected error, got: %v, want: nil", err)
			}

			got := req.Header.Get("User-Agent")
			if got != test.userAgent {
				t.Errorf("created request has unexpected header. got: %s, want: 'Custom Agent/2.3'", got)
			}
		})
	}
}

func TestReproLevelCoveredBy(t *testing.T) {
	check := func(level, reported ReproLevel, want bool) {
		t.Helper()
		if got := level.CoveredBy(reported); got != want {
			t.Errorf("%v.CoveredBy(%v) = %v; want %v", level, reported, got, want)
		}
	}

	check(ReproLevelNone, ReproLevelNone, true)
	check(ReproLevelNone, ReproLevelSyz, true)
	check(ReproLevelNone, ReproLevelCOnly, true)
	check(ReproLevelNone, ReproLevelC, true)

	check(ReproLevelSyz, ReproLevelNone, false)
	check(ReproLevelSyz, ReproLevelSyz, true)
	check(ReproLevelSyz, ReproLevelCOnly, true)
	check(ReproLevelSyz, ReproLevelC, true)

	check(ReproLevelCOnly, ReproLevelNone, false)
	check(ReproLevelCOnly, ReproLevelSyz, false)
	check(ReproLevelCOnly, ReproLevelCOnly, true)
	check(ReproLevelCOnly, ReproLevelC, true)

	check(ReproLevelC, ReproLevelNone, false)
	check(ReproLevelC, ReproLevelSyz, false)
	check(ReproLevelC, ReproLevelCOnly, true) // COnly has C repro, which covers C (both C and Syz)
	check(ReproLevelC, ReproLevelC, true)
}

func TestReproLevelFromCAndSyz(t *testing.T) {
	tests := []struct {
		hasC   bool
		hasSyz bool
		want   ReproLevel
	}{
		{false, false, ReproLevelNone},
		{false, true, ReproLevelSyz},
		{true, false, ReproLevelCOnly},
		{true, true, ReproLevelC},
	}

	for _, test := range tests {
		got := ReproLevelFromCAndSyz(test.hasC, test.hasSyz)
		if got != test.want {
			t.Errorf("reproLevelFromCAndSyz(%t, %t) = %v; want %v", test.hasC, test.hasSyz, got, test.want)
		}
	}
}

func TestReproLevelCombine(t *testing.T) {
	tests := []struct {
		level ReproLevel
		other ReproLevel
		want  ReproLevel
	}{
		{ReproLevelNone, ReproLevelNone, ReproLevelNone},
		{ReproLevelNone, ReproLevelSyz, ReproLevelSyz},
		{ReproLevelNone, ReproLevelCOnly, ReproLevelCOnly},
		{ReproLevelNone, ReproLevelC, ReproLevelC},

		{ReproLevelSyz, ReproLevelNone, ReproLevelSyz},
		{ReproLevelSyz, ReproLevelSyz, ReproLevelSyz},
		{ReproLevelSyz, ReproLevelCOnly, ReproLevelC},
		{ReproLevelSyz, ReproLevelC, ReproLevelC},

		{ReproLevelCOnly, ReproLevelNone, ReproLevelCOnly},
		{ReproLevelCOnly, ReproLevelSyz, ReproLevelC},
		{ReproLevelCOnly, ReproLevelCOnly, ReproLevelCOnly},
		{ReproLevelCOnly, ReproLevelC, ReproLevelC},

		{ReproLevelC, ReproLevelNone, ReproLevelC},
		{ReproLevelC, ReproLevelSyz, ReproLevelC},
		{ReproLevelC, ReproLevelCOnly, ReproLevelC},
		{ReproLevelC, ReproLevelC, ReproLevelC},
	}

	for _, test := range tests {
		got := test.level.Combine(test.other)
		if got != test.want {
			t.Errorf("%v.Combine(%v) = %v; want %v", test.level, test.other, got, test.want)
		}
	}
}

func TestReproLevelRank(t *testing.T) {
	tests := []struct {
		level ReproLevel
		want  int
	}{
		{ReproLevelNone, 0},
		{ReproLevelSyz, 1},
		{ReproLevelCOnly, 2},
		{ReproLevelC, 3},
	}

	for _, test := range tests {
		got := test.level.Rank()
		if got != test.want {
			t.Errorf("%v.Rank() = %v; want %v", test.level, got, test.want)
		}
	}
}
