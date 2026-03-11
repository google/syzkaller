// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dungeon

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestResolveClass(t *testing.T) {
	tests := []struct {
		name          string
		subsystems    map[string]int
		expectedName  string
		expectedEmoji string
	}{
		{
			name:          "warrior_fallback_empty",
			subsystems:    map[string]int{},
			expectedName:  "Warrior",
			expectedEmoji: "⚔️",
		},
		{
			name:          "warrior_fallback_unknown",
			subsystems:    map[string]int{"unknown": 10},
			expectedName:  "Warrior",
			expectedEmoji: "⚔️",
		},
		{
			name:          "winner_known",
			subsystems:    map[string]int{"net": 5, "fs": 2},
			expectedName:  "Weaver",
			expectedEmoji: "🕸️",
		},
		{
			name:          "tie_breaker",
			subsystems:    map[string]int{"mm": 5, "net": 5},
			expectedName:  "Voidwalker", // mm wins over net alphabetically
			expectedEmoji: "🔮",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			name, emoji, _ := ResolveClass(tc.subsystems)
			require.Equal(t, tc.expectedName, name)
			require.Equal(t, tc.expectedEmoji, emoji)
		})
	}
}

func TestCalculateLevel(t *testing.T) {
	tests := []struct {
		score    int
		expected int
	}{
		{0, 1},
		{999, 1},
		{1000, 2},
		{2000, 3},
		{48000, 49},
		{49000, 50},
		{50000, 50},
		{50500, 51},
		{52500, 52},
		{736500, 100},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("Score_%d", tc.score), func(t *testing.T) {
			result := CalculateLevel(tc.score)
			require.Equal(t, tc.expected, result)
		})
	}
}

func TestScaleAttribute(t *testing.T) {
	tests := []struct {
		rawVal   float64
		base     float64
		factor   float64
		expected int
	}{
		{0.1, 3, 4, 3},
		{10, 3, 4, 7},
		{100, 3, 4, 11},
	}

	for _, tc := range tests {
		t.Run("Scaling", func(t *testing.T) {
			result := ScaleAttribute(tc.rawVal, tc.base, tc.factor)
			require.Equal(t, tc.expected, result)
		})
	}
}

func TestIntegrationBadges(t *testing.T) {
	badges := GetBadges()
	badgeMap := make(map[string]BadgeDefinition)
	for _, b := range badges {
		badgeMap[b.Name] = b
	}

	tests := []struct {
		badgeName     string
		title         string
		expectedEmoji string
	}{
		{"Locksmith", "fix a deadlock in foo", "🗝️"},
		{"Locksmith", "locking is broken", "🗝️"},
		{"Locksmith", "use mutex to fix race", "🗝️"},
		{"Sealer", "memory-leak in fs", "🏺"},
		{"Exorcist", "info: task hung in something", "🕯️"},
		{"Abyss Walker", "fix null pointer dereference", "🕳️"},
	}

	for _, tc := range tests {
		t.Run(tc.title, func(t *testing.T) {
			b, ok := badgeMap[tc.badgeName]
			require.True(t, ok)
			bug := BugInfo{LowerTitle: tc.title}
			require.True(t, b.Predicate(bug, 0))
		})
	}
}

func TestGetKingdom(t *testing.T) {
	tests := []struct {
		email    string
		expected string
	}{
		{"user@google.com", "The Google Kingdom"},
		{"user@chromium.org", "The Google Kingdom"},
		{"user@redhat.com", "The Red Hat Kingdom"},
		{"user@unknown.com", "The Independent Mercenaries"},
		{"invalidemail", "The Independent Mercenaries"},
	}

	for _, tc := range tests {
		t.Run(tc.email, func(t *testing.T) {
			result := GetKingdom(tc.email)
			require.Equal(t, tc.expected, result)
		})
	}
}

func TestGetBugXPAndDays(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name         string
		bug          BugInfo
		expectedXP   int
		expectedDays int
	}{
		{
			name: "base_xp_only",
			bug: BugInfo{
				NumCrashes:      0,
				LacksReproducer: false,
			},
			expectedXP:   100,
			expectedDays: 0,
		},
		{
			name: "boss_bonus_max",
			bug: BugInfo{
				NumCrashes:      6000,
				LacksReproducer: false,
			},
			expectedXP:   600, // 100 base + 500 max boss
			expectedDays: 0,
		},
		{
			name: "ancient_evil",
			bug: BugInfo{
				NumCrashes:      0,
				LacksReproducer: false,
				FirstTime:       now,
				FixTime:         now.Add(24 * 365 * time.Hour), // 365 days
			},
			expectedXP:   400, // 100 base + 300 max ancient evil
			expectedDays: 365,
		},
		{
			name: "windwalker_bonus",
			bug: BugInfo{
				NumCrashes:      0,
				LacksReproducer: false,
				FirstTime:       now,
				FixTime:         now.Add(24 * 3 * time.Hour), // 3 days
			},
			expectedXP:   353, // 100 base + 3 ancient evil + 250 windwalker
			expectedDays: 3,   // 3 full days of 24h
		},
		{
			name: "blind_bonus",
			bug: BugInfo{
				NumCrashes:      0,
				LacksReproducer: true, // No repro.
			},
			expectedXP:   250, // 100 + 150 blind
			expectedDays: 0,
		},
		{
			name: "negative_days_open",
			bug: BugInfo{
				NumCrashes:      0,
				LacksReproducer: false,
				FirstTime:       now,
				FixTime:         now.Add(-24 * 5 * time.Hour), // -5 days
			},
			expectedXP:   100, // 100 Base (Windwalker dropped for negative skew)
			expectedDays: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			xp, days := GetBugXPAndDays(tc.bug)
			require.Equal(t, tc.expectedXP, xp)
			require.Equal(t, tc.expectedDays, days)
		})
	}
}

func TestGetKingdomTier(t *testing.T) {
	tests := []struct {
		score        int
		expectedTier string
	}{
		{0, "Outpost"},
		{49999, "Outpost"},
		{50000, "Barony"},
		{149999, "Barony"},
		{150000, "Duchy"},
		{499999, "Duchy"},
		{500000, "Kingdom"},
		{999999, "Kingdom"},
		{1000000, "Empire"},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("Score_%d", tc.score), func(t *testing.T) {
			result := GetKingdomTier(tc.score)
			require.Equal(t, tc.expectedTier, result.Tier)
		})
	}
}

func TestGetKingdomGuilds(t *testing.T) {
	tests := []struct {
		name     string
		counts   map[string]int
		expected []FormattedGuild
	}{
		{
			name:   "single_guild",
			counts: map[string]int{"⚔️": 1},
			expected: []FormattedGuild{
				{Emoji: "⚔️", Name: "1 Warrior"},
			},
		},
		{
			name:   "multiple_guilds_sorted",
			counts: map[string]int{"⚔️": 1, "🕸️": 2},
			expected: []FormattedGuild{
				{Emoji: "🕸️", Name: "2 Weavers"},
				{Emoji: "⚔️", Name: "1 Warrior"},
			},
		},
		{
			name:   "tie_breaker_names",
			counts: map[string]int{"⚔️": 2, "🕸️": 2},
			expected: []FormattedGuild{
				{Emoji: "⚔️", Name: "2 Warriors"},
				{Emoji: "🕸️", Name: "2 Weavers"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := GetKingdomGuilds(tc.counts)
			require.Equal(t, tc.expected, result)
		})
	}
}
