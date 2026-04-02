// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/dungeon"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/image"
	"google.golang.org/appengine/v2"
	db "google.golang.org/appengine/v2/datastore"
	"google.golang.org/appengine/v2/log"
	"google.golang.org/appengine/v2/memcache"
)

type uiDungeonBadge struct {
	Emoji string `json:"emoji"`
	Name  string `json:"name"`
	Desc  string `json:"desc"`
}

type uiDungeonPlayer struct {
	ID         string           `json:"id"`
	Name       string           `json:"name"`
	Rank       int              `json:"rank"`
	Score      int              `json:"score"`
	Level      int              `json:"level"`
	ClassName  string           `json:"class_name"`
	ClassEmoji string           `json:"class_emoji"`
	ClassDesc  string           `json:"class_desc"`
	Badges     []uiDungeonBadge `json:"badges"`
	BugCount   int              `json:"bug_count"`
	Str        int              `json:"str"`
	Int        int              `json:"int"`
	Wis        int              `json:"wis"`
	Email      string           `json:"-"`
	Kingdom    string           `json:"-"`
	KingdomID  string           `json:"-"`
	Names      map[string]int   `json:"-"`
	Subsystems map[string]int   `json:"-"`
	Bugs       []*Bug           `json:"-"`
}

type uiDungeonKingdom struct {
	ID            string           `json:"id"`
	Name          string           `json:"name"`
	Rank          int              `json:"rank"`
	Score         int              `json:"score"`
	Tier          string           `json:"tier"`
	TierEmoji     string           `json:"tier_emoji"`
	TierDesc      string           `json:"tier_desc"`
	ChampionName  string           `json:"champion_name"`
	ChampionScore int              `json:"champion_score"`
	ChampionID    string           `json:"champion_id"`
	Trophies      int              `json:"trophies"`
	Heroes        int              `json:"heroes"`
	Guilds        []uiDungeonBadge `json:"guilds"`

	AuthorMap map[string]bool `json:"-"`
}

type uiDungeonMeta struct {
	GeneratedAt time.Time `json:"generated_at"`
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
}

type uiDungeonPage struct {
	Header        *uiHeader                    `json:"-"`
	Meta          uiDungeonMeta                `json:"meta"`
	Heroes1Y      []*uiDungeonPlayer           `json:"heroes_1y"`
	HeroesAll     []*uiDungeonPlayer           `json:"heroes_all"`
	Kingdoms1Y    []*uiDungeonKingdom          `json:"kingdoms_1y"`
	KingdomsAll   []*uiDungeonKingdom          `json:"kingdoms_all"`
	HeroMap1Y     map[string]*uiDungeonPlayer  `json:"-"`
	HeroMapAll    map[string]*uiDungeonPlayer  `json:"-"`
	KingdomMap1Y  map[string]*uiDungeonKingdom `json:"-"`
	KingdomMapAll map[string]*uiDungeonKingdom `json:"-"`
}

func (p *uiDungeonPage) rebuildMaps() {
	p.HeroMapAll = make(map[string]*uiDungeonPlayer)
	for _, h := range p.HeroesAll {
		p.HeroMapAll[h.ID] = h
	}

	p.HeroMap1Y = make(map[string]*uiDungeonPlayer)
	for _, h := range p.Heroes1Y {
		p.HeroMap1Y[h.ID] = h
	}

	p.KingdomMapAll = make(map[string]*uiDungeonKingdom)
	for _, k := range p.KingdomsAll {
		p.KingdomMapAll[k.ID] = k
	}

	p.KingdomMap1Y = make(map[string]*uiDungeonKingdom)
	for _, k := range p.Kingdoms1Y {
		p.KingdomMap1Y[k.ID] = k
	}
}

const dungeonCacheDuration = time.Hour

func extractSubsystems(bug *Bug) []string {
	var ret []string
	for _, label := range bug.Labels {
		if label.Label == SubsystemLabel {
			ret = append(ret, label.Value)
		}
	}
	return ret
}

// handleDungeon serves the main Syzkaller Dungeon page.
func handleDungeon(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	hdr, err := commonHeader(ctx, r, w, "")
	if err != nil {
		return err
	}
	accessLevel := accessLevel(ctx, r)
	if hdr.Namespace != getConfig(ctx).DungeonNamespace {
		return ErrClientNotFound
	}
	data, err := getDungeonData(ctx, accessLevel, hdr.Namespace)
	if err != nil {
		return err
	}
	data.Header = hdr

	if r.FormValue("json") == "1" {
		w.Header().Set("Content-Type", "application/json")
		return writeJSONVersionOf(w, data)
	}

	return serveTemplate(w, "dungeon.html", data)
}

// handleHeroProfile serves an individual Hero's profile page.
// Refactoring out the identical HTTP handler boilerplate would reduce code readability.
// nolint:dupl
func handleHeroProfile(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	hdr, err := commonHeader(ctx, r, w, "")
	if err != nil {
		return err
	}
	accessLevel := accessLevel(ctx, r)
	if hdr.Namespace != getConfig(ctx).DungeonNamespace {
		return ErrClientNotFound
	}

	// Extract the ID from the URL: /upstream/syz-dungeon/hero/abcdef12
	heroID := r.PathValue("id")

	era := r.FormValue("era")
	if era != "1y" {
		era = "all"
	}

	data, err := getDungeonData(ctx, accessLevel, hdr.Namespace)
	if err != nil {
		return err
	}

	hero1Y := data.HeroMap1Y[heroID]
	heroAll := data.HeroMapAll[heroID]

	if hero1Y == nil && heroAll == nil {
		return ErrClientNotFound
	}

	type ProfilePage struct {
		Header     *uiHeader
		HeroName   string
		Hero1Y     *uiDungeonPlayer
		HeroAll    *uiDungeonPlayer
		All        *uiDungeonPage
		CurrentEra string
		Has1Y      bool
		HasAll     bool
	}

	heroName := ""
	if hero1Y != nil {
		heroName = hero1Y.Name
	} else if heroAll != nil {
		heroName = heroAll.Name
	}

	page := &ProfilePage{
		Header:     hdr,
		HeroName:   heroName,
		Hero1Y:     hero1Y,
		HeroAll:    heroAll,
		All:        data,
		CurrentEra: era,
		Has1Y:      hero1Y != nil,
		HasAll:     heroAll != nil,
	}

	if r.FormValue("json") == "1" {
		w.Header().Set("Content-Type", "application/json")
		if era == "1y" {
			return writeJSONVersionOf(w, hero1Y)
		}
		return writeJSONVersionOf(w, heroAll)
	}

	return serveTemplate(w, "dungeon-hero.html", page)
}

// handleKingdomProfile serves an individual Kingdom's profile page.
// Refactoring out the identical HTTP handler boilerplate would reduce code readability.
// nolint:dupl
func handleKingdomProfile(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	hdr, err := commonHeader(ctx, r, w, "")
	if err != nil {
		return err
	}
	accessLevel := accessLevel(ctx, r)
	if hdr.Namespace != getConfig(ctx).DungeonNamespace {
		return ErrClientNotFound
	}

	// Extract the ID from the URL: /upstream/syz-dungeon/kingdom/abcdef12
	kingdomID := r.PathValue("id")

	era := r.FormValue("era")
	if era != "1y" {
		era = "all"
	}

	data, err := getDungeonData(ctx, accessLevel, hdr.Namespace)
	if err != nil {
		return err
	}

	kingdom1Y := data.KingdomMap1Y[kingdomID]
	kingdomAll := data.KingdomMapAll[kingdomID]

	if kingdom1Y == nil && kingdomAll == nil {
		return ErrClientNotFound
	}

	type ProfilePage struct {
		Header      *uiHeader
		KingdomName string
		Kingdom1Y   *uiDungeonKingdom
		KingdomAll  *uiDungeonKingdom
		All         *uiDungeonPage
		CurrentEra  string
		Has1Y       bool
		HasAll      bool
	}

	kingdomName := ""
	if kingdom1Y != nil {
		kingdomName = kingdom1Y.Name
	} else if kingdomAll != nil {
		kingdomName = kingdomAll.Name
	}

	page := &ProfilePage{
		Header:      hdr,
		KingdomName: kingdomName,
		Kingdom1Y:   kingdom1Y,
		KingdomAll:  kingdomAll,
		All:         data,
		CurrentEra:  era,
		Has1Y:       kingdom1Y != nil,
		HasAll:      kingdomAll != nil,
	}

	if r.FormValue("json") == "1" {
		w.Header().Set("Content-Type", "application/json")
		if era == "1y" {
			return writeJSONVersionOf(w, kingdom1Y)
		}
		return writeJSONVersionOf(w, kingdomAll)
	}

	return serveTemplate(w, "dungeon-kingdom.html", page)
}

func addBugToPlayerMap(m map[string]*uiDungeonPlayer, email, name string, bug *Bug, xp int) {
	p, ok := m[email]
	if !ok {
		p = &uiDungeonPlayer{
			Name:       "",
			Names:      make(map[string]int),
			Subsystems: make(map[string]int),
			Bugs:       []*Bug{},
		}
		m[email] = p
	}
	if name != "" {
		p.Names[name]++
	}
	// Note: We also track the email in case we have to fall back to it.
	p.Email = email

	p.Bugs = append(p.Bugs, bug)
	p.BugCount++

	subsystems := extractSubsystems(bug)
	for _, sub := range subsystems {
		p.Subsystems[sub]++
	}
	p.Score += xp
}

func addBugToKingdomMap(m map[string]*uiDungeonKingdom, name, author string, bug *Bug, newBugForKingdom bool) {
	k, ok := m[name]
	if !ok {
		k = &uiDungeonKingdom{
			Name:      name,
			AuthorMap: make(map[string]bool),
		}
		m[name] = k
	}
	if !k.AuthorMap[author] {
		k.AuthorMap[author] = true
		k.Heroes++
	}

	if newBugForKingdom {
		k.Trophies++
	}
}

func dungeonCacheKey(access AccessLevel) string {
	return fmt.Sprintf("dungeon-%d", access)
}

func getDungeonData(ctx context.Context, access AccessLevel, ns string) (*uiDungeonPage, error) {
	// Check memcache.
	item, err := memcache.Get(ctx, dungeonCacheKey(access))
	if err == nil {
		jsonData, destructor := image.MustDecompress(item.Value)
		defer destructor()
		var page uiDungeonPage
		if err := json.Unmarshal(jsonData, &page); err == nil {
			page.rebuildMaps()
			return &page, nil
		}
	}

	// Fetch from Datastore if miss.
	page, err := fetchDungeonData(ctx, access, ns)
	if err != nil {
		return nil, err
	}

	encoded, err := json.Marshal(page)
	if err != nil {
		return nil, err
	}

	item = &memcache.Item{
		Key:        dungeonCacheKey(access),
		Value:      image.Compress(encoded),
		Expiration: dungeonCacheDuration,
	}
	if err := memcache.Set(ctx, item); err != nil {
		return nil, err
	}

	return page, nil
}

func handleDungeonPreheat(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)
	for _, accessLevel := range []AccessLevel{AccessPublic, AccessUser, AccessAdmin} {
		page, err := fetchDungeonData(ctx, accessLevel, getConfig(ctx).DungeonNamespace)
		if err != nil {
			log.Errorf(ctx, "failed to preheat dungeon for access %v: %v", accessLevel, err)
			continue
		}

		encoded, err := json.Marshal(page)
		if err != nil {
			log.Errorf(ctx, "failed to marshal dungeon preheat for access %v: %v", accessLevel, err)
			continue
		}

		item := &memcache.Item{
			Key:        dungeonCacheKey(accessLevel),
			Value:      image.Compress(encoded),
			Expiration: dungeonCacheDuration,
		}
		if err := memcache.Set(ctx, item); err != nil {
			log.Errorf(ctx, "failed to store dungeon preheat for access %v: %v", accessLevel, err)
			continue
		}
	}
}

func fetchDungeonData(ctx context.Context, access AccessLevel, ns string) (*uiDungeonPage, error) {
	now := timeNow(ctx)
	cutoff := now.UTC().AddDate(-1, 0, 0)

	bugs, _, err := loadAllBugs(ctx, func(query *db.Query) *db.Query {
		return query.Filter("Namespace=", ns).Filter("Status=", BugStatusFixed)
	})
	if err != nil {
		return nil, err
	}

	partial, _, err := loadAllBugs(ctx, func(query *db.Query) *db.Query {
		return query.Filter("Namespace=", ns).Filter("Status=", BugStatusOpen).Filter("Commits>", "")
	})
	if err != nil {
		return nil, err
	}
	bugs = append(bugs, partial...)

	playerMap1Y := make(map[string]*uiDungeonPlayer)
	playerMapAll := make(map[string]*uiDungeonPlayer)
	kingdomMap1Y := make(map[string]*uiDungeonKingdom)
	kingdomMapAll := make(map[string]*uiDungeonKingdom)

	bugDays := make(map[*Bug]int, len(bugs))

	for _, bug := range bugs {
		if access < bug.sanitizeAccess(ctx, access) {
			continue
		}
		in1Y := !bug.FixTime.IsZero() && !bug.FixTime.Before(cutoff)
		bugInfo := dungeon.BugInfo{
			NumCrashes:      int(bug.NumCrashes),
			LacksReproducer: bug.ReproLevel == dashapi.ReproLevelNone,
			FirstTime:       bug.FirstTime,
			FixTime:         bug.FixTime,
		}
		xp, daysOpen := dungeon.GetBugXPAndDays(bugInfo)
		bugDays[bug] = daysOpen

		accreditedEmails := make(map[string]bool)
		creditedKingdomsAll := make(map[string]bool)
		creditedKingdoms1Y := make(map[string]bool)

		for _, ci := range bug.CommitInfo {
			playerEmail := ci.Author
			if playerEmail == "" {
				continue
			}

			playerEmail = strings.ToLower(strings.TrimSpace(playerEmail))

			if accreditedEmails[playerEmail] {
				continue
			}
			accreditedEmails[playerEmail] = true

			playerName := strings.TrimSpace(ci.AuthorName)

			addBugToPlayerMap(playerMapAll, playerEmail, playerName, bug, xp)
			if in1Y {
				addBugToPlayerMap(playerMap1Y, playerEmail, playerName, bug, xp)
			}

			domain := dungeon.GetKingdom(playerEmail)

			newForKingdomAll := !creditedKingdomsAll[domain]
			creditedKingdomsAll[domain] = true
			addBugToKingdomMap(kingdomMapAll, domain, playerEmail, bug, newForKingdomAll)

			if in1Y {
				newForKingdom1Y := !creditedKingdoms1Y[domain]
				creditedKingdoms1Y[domain] = true
				addBugToKingdomMap(kingdomMap1Y, domain, playerEmail, bug, newForKingdom1Y)
			}
		}
	}

	page := &uiDungeonPage{
		Meta: uiDungeonMeta{
			GeneratedAt: now,
			WindowStart: cutoff,
			WindowEnd:   now,
		},
	}

	page.Heroes1Y = processPlayers(playerMap1Y, bugDays)
	page.HeroesAll = processPlayers(playerMapAll, bugDays)
	page.KingdomsAll = processKingdoms(kingdomMapAll, page.HeroesAll)
	page.Kingdoms1Y = processKingdoms(kingdomMap1Y, page.Heroes1Y)

	page.HeroMapAll = make(map[string]*uiDungeonPlayer)
	for _, p := range page.HeroesAll {
		page.HeroMapAll[p.ID] = p
	}

	page.HeroMap1Y = make(map[string]*uiDungeonPlayer)
	for _, p := range page.Heroes1Y {
		page.HeroMap1Y[p.ID] = p
	}

	page.KingdomMapAll = make(map[string]*uiDungeonKingdom)
	for _, k := range page.KingdomsAll {
		page.KingdomMapAll[k.ID] = k
	}

	page.KingdomMap1Y = make(map[string]*uiDungeonKingdom)
	for _, k := range page.Kingdoms1Y {
		page.KingdomMap1Y[k.ID] = k
	}

	return page, nil
}

func processPlayers(playerMap map[string]*uiDungeonPlayer, bugDays map[*Bug]int) []*uiDungeonPlayer {
	var hallOfFame []*uiDungeonPlayer

	for _, p := range playerMap {
		p.ClassName, p.ClassEmoji, p.ClassDesc = dungeon.ResolveClass(p.Subsystems)

		p.Name = dungeon.GetHeroName(p.Email, p.Names)
		p.Kingdom = dungeon.GetKingdom(p.Email)
		p.KingdomID = hashEmailID(p.Kingdom)

		// Calculate Badges.
		var badges []uiDungeonBadge

		awardedBadges := make(map[string]bool)

		for _, bug := range p.Bugs {
			daysOpen := bugDays[bug]

			lowerTitle := strings.ToLower(bug.Title)
			var lowerCommitTitles []string
			for _, commit := range bug.CommitInfo {
				lowerCommitTitles = append(lowerCommitTitles, strings.ToLower(commit.Title))
			}

			bugInfo := dungeon.BugInfo{
				LowerTitle:        lowerTitle,
				LowerCommitTitles: lowerCommitTitles,
				DaysOpen:          daysOpen,
				NumCrashes:        int(bug.NumCrashes),
				LacksReproducer:   bug.ReproLevel == dashapi.ReproLevelNone,
				HoursToFix:        -1,
			}
			if !bug.FixTime.IsZero() && !bug.FirstTime.IsZero() {
				bugInfo.HoursToFix = int(bug.FixTime.Sub(bug.FirstTime).Hours())
			}
			for _, def := range dungeon.GetBadges() {
				if !awardedBadges[def.Name] && def.Predicate(bugInfo, len(p.Bugs)) {
					badges = append(badges, uiDungeonBadge{Emoji: def.Emoji, Name: def.Name})
					awardedBadges[def.Name] = true
				}
			}

			// Calculate Attributes (Raw values tracked here, scaled later).
			// Str: Max Crashes.
			p.Str = max(p.Str, int(bug.NumCrashes))
			// Int: Blind Fixes Count.
			if bug.ReproLevel == dashapi.ReproLevelNone {
				p.Int++
			}
			// Wis: Max Days Open.
			p.Wis = max(p.Wis, daysOpen)
		}

		// Scale Attributes.
		strRaw := float64(p.Str)
		strRaw = max(strRaw, 1)
		p.Str = dungeon.ScaleAttribute(strRaw, 3, 4)
		p.Int = dungeon.ScaleAttribute(float64(p.Int)+1, 3, 10)
		p.Wis = dungeon.ScaleAttribute(float64(p.Wis)+1, 3, 5)

		sort.Slice(badges, func(i, j int) bool {
			return badges[i].Name < badges[j].Name
		})

		p.Badges = badges

		p.Level = dungeon.CalculateLevel(p.Score)

		p.ID = hashEmailID(p.Email)

		hallOfFame = append(hallOfFame, p)
	}

	sort.Slice(hallOfFame, func(i, j int) bool {
		// Secondary sort by Name ascending.
		if hallOfFame[i].Score == hallOfFame[j].Score {
			if hallOfFame[i].Name == hallOfFame[j].Name {
				return hallOfFame[i].Email < hallOfFame[j].Email
			}
			return hallOfFame[i].Name < hallOfFame[j].Name
		}
		return hallOfFame[i].Score > hallOfFame[j].Score
	})

	for i, p := range hallOfFame {
		p.Rank = i + 1
	}

	return hallOfFame
}

func processKingdoms(kingdomMap map[string]*uiDungeonKingdom, heroes []*uiDungeonPlayer) []*uiDungeonKingdom {
	var hallOfFame []*uiDungeonKingdom
	for _, k := range kingdomMap {
		guildsMapEmojiCount := make(map[string]int)

		var champName string
		var champScore int
		var champID string

		for _, h := range heroes {
			if h.Kingdom == k.Name {
				guildsMapEmojiCount[h.ClassEmoji]++
				k.Score += h.Score

				if h.Score > champScore {
					champScore = h.Score
					champName = h.Name
					champID = h.ID
				}
			}
		}

		k.ChampionName = champName
		k.ChampionScore = champScore
		k.ChampionID = champID

		guilds := dungeon.GetKingdomGuilds(guildsMapEmojiCount)
		k.Guilds = nil
		for _, g := range guilds {
			k.Guilds = append(k.Guilds, uiDungeonBadge{Emoji: g.Emoji, Name: g.Name})
		}

		tier := dungeon.GetKingdomTier(k.Score)
		k.Tier = tier.Tier
		k.TierEmoji = tier.TierEmoji
		k.TierDesc = tier.TierDesc

		k.ID = hashEmailID(k.Name)
		hallOfFame = append(hallOfFame, k)
	}

	sort.Slice(hallOfFame, func(i, j int) bool {
		if hallOfFame[i].Score == hallOfFame[j].Score {
			return hallOfFame[i].Name < hallOfFame[j].Name
		}
		return hallOfFame[i].Score > hallOfFame[j].Score
	})

	for i, k := range hallOfFame {
		k.Rank = i + 1
	}

	return hallOfFame
}

// hashEmailID takes a lowercased email, hashes it using pkg/hash, and returns the first 16 hex characters.
func hashEmailID(email string) string {
	if email == "" {
		return ""
	}
	return hash.String(email)[:16]
}
