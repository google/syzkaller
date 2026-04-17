// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/stretchr/testify/require"
)

func TestHashEmailID(t *testing.T) {
	tests := []struct {
		email    string
		expected string
	}{
		{"", ""},
		{"test@example.com", "567159d622ffbb50"},
	}

	for _, tc := range tests {
		t.Run(tc.email, func(t *testing.T) {
			result := hashEmailID(tc.email)
			require.Equal(t, tc.expected, result)
		})
	}
}

func TestProcessPlayers(t *testing.T) {
	now := time.Now()

	bug1 := &Bug{
		NumCrashes: 1500,                   // Dragon Slayer.
		ReproLevel: dashapi.ReproLevelNone, // Diviner.
		FirstTime:  now,
		FixTime:    now.Add(24 * 400 * time.Hour), // 400 days -> Necromancer
	}

	bug2 := &Bug{
		Title:      "memory-leak in fs", // Sealer.
		NumCrashes: 10,
		ReproLevel: dashapi.ReproLevelC,
		FirstTime:  now,
		FixTime:    now.Add(24 * 2 * time.Hour), // 2 days -> Windwalker
	}

	bugDays := map[*Bug]int{
		bug1: 400,
		bug2: 2,
	}

	playerMap := map[string]*uiDungeonPlayer{
		"hero1@test.com": {
			Email:      "hero1@test.com",
			Names:      map[string]int{"Bob": 1},
			Bugs:       []*Bug{bug1, bug2},
			Subsystems: map[string]int{"fs": 1},
			Score:      1000,
		},
	}

	// Also add a Hydra Hunter.
	bugs := make([]*Bug, 11)
	for i := range 11 {
		b := &Bug{NumCrashes: 1}
		bugs[i] = b
		bugDays[b] = 1
	}
	playerMap["hero2@test.com"] = &uiDungeonPlayer{
		Email: "hero2@test.com",
		Bugs:  bugs,
	}

	players := processPlayers(playerMap, bugDays)
	require.Equal(t, 2, len(players))

	var hero1, hero2 *uiDungeonPlayer
	for _, p := range players {
		switch p.Email {
		case "hero1@test.com":
			hero1 = p
		case "hero2@test.com":
			hero2 = p
		}
	}

	// Verify Hero 1 badges.
	badges := make(map[string]bool)
	for _, b := range hero1.Badges {
		badges[b.Name] = true
	}

	expectedBadges := []string{"Dragon Vanquisher", "Necromancer", "Diviner", "Windwalker", "Sealer"}
	for _, eb := range expectedBadges {
		require.True(t, badges[eb])
	}

	// Verify Hero 2 badges (Hydra Hunter).
	badges2 := make(map[string]bool)
	for _, b := range hero2.Badges {
		badges2[b.Name] = true
	}
	require.True(t, badges2["Hydra Hunter"])

	// Verify Attribute scaling.
	// Hero 1 Str raw = 1500 -> int(3 + 4*log10(1500)) = int(3 + 4*3.176) = 15
	require.Equal(t, 15, hero1.Str)

	// Hero 1 Wis raw = 400. Wis is scaleAttribute(401, 3, 5). log10(401) = 2.6
	// 3 + 5 * 2.6 = 16
	require.Equal(t, 16, hero1.Wis)
}

func TestProcessKingdoms(t *testing.T) {
	kingdomMap := map[string]*uiDungeonKingdom{
		"The Google Kingdom": {
			Name: "The Google Kingdom",
		},
		"The Red Hat Kingdom": {
			Name: "The Red Hat Kingdom",
		},
	}

	heroes := []*uiDungeonPlayer{
		{
			Kingdom:    "The Google Kingdom",
			Score:      1500,
			ClassEmoji: "🏔️", // Geomancer.
		},
		{
			Kingdom:    "The Google Kingdom",
			Score:      2500,
			ClassEmoji: "🕸️", // Weaver.
		},
		{
			Kingdom:    "The Google Kingdom",
			Score:      500,
			ClassEmoji: "🕸️", // Weaver.
		},
		{
			Kingdom:    "The Red Hat Kingdom",
			Score:      1000,
			ClassEmoji: "⚔️", // Warrior.
		},
	}

	kingdoms := processKingdoms(kingdomMap, heroes)
	require.Equal(t, 2, len(kingdoms))

	// Google should have score 4500, rank 1
	require.Equal(t, "The Google Kingdom", kingdoms[0].Name)
	require.Equal(t, 4500, kingdoms[0].Score)
	require.Equal(t, 1, kingdoms[0].Rank)

	require.Equal(t, "The Red Hat Kingdom", kingdoms[1].Name)
	require.Equal(t, 1000, kingdoms[1].Score)
	require.Equal(t, 2, kingdoms[1].Rank)

	guilds := kingdoms[0].Guilds
	require.Equal(t, 2, len(guilds))

	// Sorted by count descending, then alphabetically (Weavers > Geomancers but they have different counts).
	require.Equal(t, "2 Weavers", guilds[0].Name)
	require.Equal(t, "🕸️", guilds[0].Emoji)

	require.Equal(t, "1 Geomancer", guilds[1].Name)
	require.Equal(t, "🏔️", guilds[1].Emoji)
}

func TestIntegrationBadges(t *testing.T) {
	tests := []struct {
		title         string
		expectedBadge string // emoji
	}{
		// Locksmith.
		{"fix a deadlock in foo", "🗝️"},
		{"locking is broken", "🗝️"},
		{"use mutex to fix race", "🗝️"},
		{"remove broken spinlock", "🗝️"},
		{"replace rwlock with rcu", "🗝️"},
		{"random lockup on boot", "🗝️"},
		{"unlock the resource", "🗝️"},
		{"add some locks here", "🗝️"},
		{"prevent recursive lock", "🗝️"},
		// The Exorcist.
		{"info: task hung in something", "🕯️"},
		{"fix transition to TaskExitZombie", "🕯️"},
		// The Abyss Walker.
		{"fix null pointer dereference", "🕳️"},
		{"KASAN: null-ptr-deref in foo", "🕳️"},
		// The Alchemist.
		{"fix uninit value", "⚗️"},
		{"KMSAN: uninit-value in skb", "⚗️"},
		// The Executioner.
		{"fix double-free in driver", "🪓"},
		{"KASAN: double free or invalid free", "🪓"},
		// Master of Time.
		{"replace hrtimer: with nothing", "⏳"},
		// Armorer.
		{"general protection fault in net", "⚒️"},
		// Beast Tamer.
		{"data-race in usb", "🦄"},
		// Pathfinder.
		{"out-of-bounds read", "🛶"},
		// Grave Robber.
		{"use-after-free write", "🪦"},
		// Negative matches.
		{"this is blocking the thread", ""},
		{"fix block allocation", ""},
		{"clock issue", ""},
		{"just a normal bug", ""},
		{"not a null bug", ""},
		{"initialized properly", ""},
		{"just one free", ""},
	}

	for _, tc := range tests {
		dummyBug := &Bug{Title: tc.title, ReproLevel: dashapi.ReproLevelC}
		playerMap := map[string]*uiDungeonPlayer{
			"a@test.com": {Email: "a@test.com", Bugs: []*Bug{dummyBug}},
		}

		players := processPlayers(playerMap, map[*Bug]int{})
		require.Equal(t, 1, len(players))

		hasExpected := false
		for _, b := range players[0].Badges {
			if tc.expectedBadge != "" && b.Emoji == tc.expectedBadge {
				hasExpected = true
			}
		}

		if tc.expectedBadge != "" {
			require.Truef(t, hasExpected, "title %q: expected badge %q, but not found in %v",
				tc.title, tc.expectedBadge, players[0].Badges)
		} else {
			require.Emptyf(t, players[0].Badges, "title %q: expected no badges", tc.title)
		}
	}
}

func TestTrophyLadderBadges(t *testing.T) {
	// Create a dummy bug to assign to players.
	dummyBug := &Bug{NumCrashes: 1, Title: "foo", ReproLevel: dashapi.ReproLevelC}

	tests := []struct {
		numBugs        int
		expectedBadges []string // emojis
	}{
		{9, []string{}},
		{10, []string{"🔥"}},
		{49, []string{"🔥"}},
		{50, []string{"🔥", "🧌"}},
		{105, []string{"🔥", "🧌", "🐙"}},
		{250, []string{"🔥", "🧌", "🐙", "👹"}},
		{501, []string{"🔥", "🧌", "🐙", "👹", "🔱"}},
	}

	for _, tc := range tests {
		var bugs []*Bug
		for range tc.numBugs {
			bugs = append(bugs, dummyBug)
		}

		playerMap := map[string]*uiDungeonPlayer{
			"a@test.com": {Email: "a@test.com", Bugs: bugs},
		}

		players := processPlayers(playerMap, map[*Bug]int{})
		require.Equal(t, 1, len(players))

		p := players[0]
		var playerEmojis []string
		for _, b := range p.Badges {
			playerEmojis = append(playerEmojis, b.Emoji)
		}

		// Check if player has exactly the expected badges.
		require.ElementsMatch(t, tc.expectedBadges, playerEmojis)
	}
}

func TestExtractSubsystems(t *testing.T) {
	bug := &Bug{
		Labels: []BugLabel{
			{Label: SubsystemLabel, Value: "net"},
			{Label: SubsystemLabel, Value: "fs"},
			{Label: "other", Value: "ignore_me"},
		},
	}
	subs := extractSubsystems(bug)
	require.Equal(t, []string{"net", "fs"}, subs)
}

func TestPlayerRankingTieBreakers(t *testing.T) {
	playerMap := map[string]*uiDungeonPlayer{
		"z@test.com": {Email: "z@test.com", Score: 1000, Name: "Alice", Names: map[string]int{"Alice": 1}},
		"a@test.com": {Email: "a@test.com", Score: 1000, Name: "Bob", Names: map[string]int{"Bob": 1}},
		"y@test.com": {Email: "y@test.com", Score: 1000, Name: "Alice", Names: map[string]int{"Alice": 1}},
		"c@test.com": {Email: "c@test.com", Score: 2000, Name: "Charlie", Names: map[string]int{"Charlie": 1}},
	}
	players := processPlayers(playerMap, map[*Bug]int{})
	require.Equal(t, 4, len(players))
	require.Equal(t, "c@test.com", players[0].Email)
	require.Equal(t, "y@test.com", players[1].Email)
	require.Equal(t, "z@test.com", players[2].Email)
	require.Equal(t, "a@test.com", players[3].Email)
}

func TestMultiNameAggregation(t *testing.T) {
	playerMap := map[string]*uiDungeonPlayer{
		"hero@test.com": {
			Email: "hero@test.com",
			Names: map[string]int{
				"Alice":   2,
				"Bob":     5, // Bob is most frequent.
				"Charlie": 5, // Tie with Bob.
			},
		},
	}
	players := processPlayers(playerMap, map[*Bug]int{})
	// most frequent tie: Bob and Charlie (5). Bob comes alphabetically first.
	// Bob -> Bob The Brave
	require.Equal(t, "Bob The Brave", players[0].Name)
}

func TestHeroNamingLogic(t *testing.T) {
	playerMap := map[string]*uiDungeonPlayer{
		"hero1@test.com": {Email: "hero1@test.com", Names: map[string]int{"alice": 1}},  // lowercase 'a'
		"hero2@test.com": {Email: "hero2@test.com", Names: map[string]int{"123bot": 1}}, // non-alphabetic
		"hero3@test.com": {Email: "hero3@test.com"},                                     // empty name -> fallback to email
	}
	players := processPlayers(playerMap, map[*Bug]int{})

	names := make(map[string]string)
	for _, p := range players {
		names[p.Email] = p.Name
	}

	require.Equal(t, "alice The Arcane", names["hero1@test.com"])
	require.Equal(t, "123bot The Adventurer", names["hero2@test.com"])
	require.Equal(t, "hero3@test.com", names["hero3@test.com"])
}
