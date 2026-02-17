// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dungeon

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
)

type BugInfo struct {
	LowerTitle        string
	LowerCommitTitles []string
	DaysOpen          int
	NumCrashes        int
	LacksReproducer   bool
	HoursToFix        int // Hours to fix from first crash, if fixed.
	FirstTime         time.Time
	FixTime           time.Time
}

type BadgeDefinition struct {
	Emoji       string
	Name        string
	Description string
	Predicate   func(bug BugInfo, totalBugs int) bool
}

// compileTokensRegex builds a regular expression that matches any of the tokens as whole words.
func compileTokensRegex(tokens ...string) *regexp.Regexp {
	if len(tokens) == 0 {
		return nil
	}
	var pattern strings.Builder
	pattern.WriteString(`\b(`)
	for i, t := range tokens {
		if i > 0 {
			pattern.WriteString(`|`)
		}
		pattern.WriteString(regexp.QuoteMeta(t))
	}
	pattern.WriteString(`)\b`)
	return regexp.MustCompile(pattern.String())
}

func containsAny(s string, substrings ...string) bool {
	for _, substr := range substrings {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

func checkBugAndCommits(lowerTitle string, lowerCommitTitles []string, predicate func(string) bool) bool {
	if predicate(lowerTitle) {
		return true
	}
	for _, commitTitle := range lowerCommitTitles {
		if predicate(commitTitle) {
			return true
		}
	}
	return false
}

type heroClass struct {
	Name       string
	Emoji      string
	FlavorText string
}

var CuratedKingdoms = map[string]string{
	"google.com":          "The Google Kingdom",
	"chromium.org":        "The Google Kingdom",
	"redhat.com":          "The Red Hat Kingdom",
	"huawei.com":          "The Huawei Kingdom",
	"hisilicon.com":       "The Huawei Kingdom",
	"meta.com":            "The Meta Kingdom",
	"fb.com":              "The Meta Kingdom",
	"linuxfoundation.org": "The Linux Foundation Kingdom",
	"kernel.org":          "The Linux Foundation Kingdom",
	"intel.com":           "The Intel Kingdom",
	"linux.intel.com":     "The Intel Kingdom",
	"amd.com":             "The AMD Kingdom",
	"arm.com":             "The ARM Kingdom",
	"oracle.com":          "The Oracle Kingdom",
	"suse.com":            "The SUSE Kingdom",
	"suse.de":             "The SUSE Kingdom",
	"suse.cz":             "The SUSE Kingdom",
	"linaro.org":          "The Linaro Kingdom",
	"linux.alibaba.com":   "The Alibaba Kingdom",
	"nvidia.com":          "The NVIDIA Kingdom",
	"mellanox.com":        "The NVIDIA Kingdom",
	"linux.ibm.com":       "The IBM Kingdom",
	"linux.vnet.ibm.com":  "The IBM Kingdom",
	"bytedance.com":       "The Bytedance Kingdom",
	"canonical.com":       "The Canonical Kingdom",
	"ubuntu.com":          "The Canonical Kingdom",
	"amazon.com":          "The Amazon Kingdom",
	"amazon.de":           "The Amazon Kingdom",
	"amazon.co.jp":        "The Amazon Kingdom",
	"amazon.co.uk":        "The Amazon Kingdom",
	"tencent.com":         "The Tencent Kingdom",
	"samsung.com":         "The Samsung Kingdom",
}

func GetKingdom(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "The Independent Mercenaries"
	}
	domain := parts[1]
	if kingdom, ok := CuratedKingdoms[domain]; ok {
		return kingdom
	}
	return "The Independent Mercenaries"
}

func GetBugXPAndDays(bug BugInfo) (int, int) {
	xp := 100 // Base.

	// Boss Bonus: scaling with number of crashes.
	crashBonus := int(math.Ceil(float64(bug.NumCrashes) * 0.1))
	crashBonus = min(crashBonus, 500)
	xp += crashBonus

	daysOpen := 0
	if !bug.FixTime.IsZero() && !bug.FirstTime.IsZero() {
		duration := bug.FixTime.Sub(bug.FirstTime)
		daysOpen = int(duration.Hours() / 24)
		daysOpen = max(daysOpen, 0)

		// Ancient Evil Bonus: 1 XP per day open, capped at 300.
		ageBonus := daysOpen * 1
		ageBonus = min(ageBonus, 300)
		xp += ageBonus

		// Windwalker Bonus: flat +250 XP if fixed under 7 days.
		if duration >= 0 && duration < 7*24*time.Hour {
			xp += 250
		}
	}

	// Blind Bonus: +150 XP if bug was fixed without a reproducer.
	if bug.LacksReproducer {
		xp += 150
	}

	return xp, daysOpen
}

var classDefs = []struct {
	Name        string
	Emoji       string
	Description string
	Subsystems  []string
}{
	{"Weaver", "🕸️", "Masters of the web, spinning fixes across the stack.", []string{
		"net", "ipv4", "ipv6", "tcp", "udp", "sctp", "bpf",
		"wireless", "bluetooth", "can", "tipc", "nfc", "bridge", "netlink",
	}},
	{"Geomancer", "🏔️", "Architects shifting the bedrock of the file systems.", []string{
		"fs", "ext4", "btrfs", "xfs", "vfs", "block", "scsi", "nvme", "io-uring", "fuse", "overlayfs",
	}},
	{"Voidwalker", "🔮", "Those who stare into the null pointer void.", []string{
		"mm", "kasan", "slab", "kcsan", "kmemleak",
	}},
	{"Paladin", "🛡️", "Guardians protecting the kernel gates.", []string{
		"security", "selinux", "apparmor", "lsm", "audit", "keyrings", "crypto",
	}},
	{"Bard", "🎻", "Keepers of peripherals, ensuring the kernel sings.", []string{
		"sound", "usb", "media", "video", "drm", "gpu", "input", "hid", "drivers",
	}},
	{"Artificer", "🛠️", "Forging the hardware links that bind the machine.", []string{
		"pci", "i2c", "spi", "gpio", "clk", "pm", "dmaengine", "iio", "rtc", "watchdog",
	}},
	{"Warlock", "🌀", "Summoners of virtual worlds and guest spirits.", []string{
		"kvm", "xen", "virt", "hyperv",
	}},
	{"Rogue", "🗡️", "Specialists striking from the architecture shadows.", []string{
		"arch", "arm", "arm64", "x86", "riscv", "s390",
	}},
	{"Druid", "🌿", "Tending the roots of the scheduler and core.", []string{
		"kernel", "sched", "rcu", "locking", "trace", "cgroups",
	}},
}

var classLookup = make(map[string]heroClass)

func init() {
	for _, def := range classDefs {
		hc := heroClass{Name: def.Name, Emoji: def.Emoji, FlavorText: def.Description}
		for _, sub := range def.Subsystems {
			classLookup[sub] = hc
		}
	}
}

var HeroicAdjectives = map[byte]string{
	'a': "The Arcane",
	'b': "The Brave",
	'c': "The Cosmic",
	'd': "The Devoted",
	'e': "The Epic",
	'f': "The Fierce",
	'g': "The Gallant",
	'h': "The Heroic",
	'i': "The Immortal",
	'j': "The Just",
	'k': "The Knightly",
	'l': "The Legendary",
	'm': "The Mystic",
	'n': "The Noble",
	'o': "The Omniscient",
	'p': "The Prime",
	'q': "The Quick",
	'r': "The Radiant",
	's': "The Sacred",
	't': "The Titan",
	'u': "The Undying",
	'v': "The Valiant",
	'w': "The Wise",
	'x': "The Xenial",
	'y': "The Youthful",
	'z': "The Zealous",
}

func GetMostFrequent(m map[string]int) string {
	var maxKey string
	maxVal := -1
	for k, v := range m {
		if v > maxVal || (v == maxVal && k < maxKey) {
			maxKey = k
			maxVal = v
		}
	}
	return maxKey
}

func ResolveClass(subsystems map[string]int) (string, string, string) {
	className := "Warrior"
	classEmoji := "⚔️"
	classDesc := "The baseline class for heroes without a discernible specialization."

	mainSpec := GetMostFrequent(subsystems)
	if mainSpec != "" {
		if classInfo, ok := classLookup[mainSpec]; ok {
			className = classInfo.Name
			classEmoji = classInfo.Emoji
			classDesc = classInfo.FlavorText
		}
	}
	return className, classEmoji, classDesc
}

func GetHeroName(email string, names map[string]int) string {
	if len(names) == 0 {
		return email
	}
	name := GetMostFrequent(names)
	if name == "" {
		return email
	}
	firstChar := name[0]
	if firstChar >= 'A' && firstChar <= 'Z' {
		firstChar += 'a' - 'A'
	}
	if adj, ok := HeroicAdjectives[firstChar]; ok {
		return name + " " + adj
	}
	return name + " The Adventurer"
}

var (
	leakBadgeRegex = compileTokensRegex("leak", "leaks", "memory-leak", "memory-leaks")
	lockBadgeRegex = compileTokensRegex(
		"lock", "deadlock", "lockup", "locking", "mutex",
		"unlock", "locks", "rwlock", "spinlock",
	)
)

func GetBadges() []BadgeDefinition {
	return []BadgeDefinition{
		{Emoji: "🐉", Name: "Dragon Vanquisher", Description: "The Scaled Slayer. Fixed a bug with over 1000 crashes.",
			Predicate: func(bug BugInfo, totalBugs int) bool { return bug.NumCrashes > 1000 }},
		{Emoji: "💀", Name: "Necromancer", Description: "The Reanimator. Resolved a bug that had been open for over a year.",
			Predicate: func(bug BugInfo, totalBugs int) bool { return bug.DaysOpen > 365 }},
		{Emoji: "👁️", Name: "Diviner", Description: "The Grave-Warden. Fixed a bug that lacked a reproducer.",
			Predicate: func(bug BugInfo, totalBugs int) bool { return bug.LacksReproducer }},
		{Emoji: "🪽", Name: "Windwalker", Description: "The Swift Message. Fixed a bug within 7 days of its first crash.",
			Predicate: func(bug BugInfo, totalBugs int) bool { return bug.HoursToFix >= 0 && bug.HoursToFix < 7*24 }},
		{Emoji: "🔥", Name: "Hydra Hunter", Description: "The Regenerating Beast. Fixed 10+ bugs.",
			Predicate: func(bug BugInfo, totalBugs int) bool { return totalBugs >= 10 }},
		{Emoji: "🧌", Name: "Troll Crusher", Description: "The Stubborn Brute. Fixed 50+ bugs.",
			Predicate: func(bug BugInfo, totalBugs int) bool { return totalBugs >= 50 }},
		{Emoji: "🐙", Name: "Kraken Bane", Description: "The Tangled Terror. Fixed 100+ bugs.",
			Predicate: func(bug BugInfo, totalBugs int) bool { return totalBugs >= 100 }},
		{Emoji: "👹", Name: "Demon Slayer", Description: "The Ancient Demon. Fixed 250+ bugs.",
			Predicate: func(bug BugInfo, totalBugs int) bool { return totalBugs >= 250 }},
		{Emoji: "🔱", Name: "Leviathan Conqueror", Description: "The Mythic Entity. Fixed 500+ bugs.",
			Predicate: func(bug BugInfo, totalBugs int) bool { return totalBugs >= 500 }},
		{Emoji: "🏺", Name: "Sealer", Description: "Fixed a memory leak.",
			Predicate: func(bug BugInfo, totalBugs int) bool {
				return checkBugAndCommits(bug.LowerTitle, bug.LowerCommitTitles, leakBadgeRegex.MatchString)
			}},
		{Emoji: "📜", Name: "Keeper of Secrets", Description: "Fixed an infoleak vulnerability.",
			Predicate: func(bug BugInfo, totalBugs int) bool {
				return checkBugAndCommits(bug.LowerTitle, bug.LowerCommitTitles, func(s string) bool {
					return containsAny(s, "infoleak")
				})
			}},
		{Emoji: "⏳", Name: "Master of Time", Description: "Fixed a time-related bug.",
			Predicate: func(bug BugInfo, totalBugs int) bool {
				return checkBugAndCommits(bug.LowerTitle, bug.LowerCommitTitles, func(s string) bool {
					return containsAny(s, "time:", "timer:")
				})
			}},
		{Emoji: "🛶", Name: "Pathfinder", Description: "Fixed an out-of-bounds error.",
			Predicate: func(bug BugInfo, totalBugs int) bool {
				return checkBugAndCommits(bug.LowerTitle, bug.LowerCommitTitles, func(s string) bool {
					return containsAny(s, "out-of-bounds")
				})
			}},
		{Emoji: "🦄", Name: "Beast Tamer", Description: "Fixed a data race.",
			Predicate: func(bug BugInfo, totalBugs int) bool {
				return checkBugAndCommits(bug.LowerTitle, bug.LowerCommitTitles, func(s string) bool {
					return containsAny(s, "data-race")
				})
			}},
		{Emoji: "⚒️", Name: "Armorer", Description: "Fixed a general protection fault.",
			Predicate: func(bug BugInfo, totalBugs int) bool {
				return checkBugAndCommits(bug.LowerTitle, bug.LowerCommitTitles, func(s string) bool {
					return containsAny(s, "general protection fault")
				})
			}},
		{Emoji: "🪦", Name: "Grave Robber", Description: "Fixed a use-after-free error.",
			Predicate: func(bug BugInfo, totalBugs int) bool {
				return checkBugAndCommits(bug.LowerTitle, bug.LowerCommitTitles, func(s string) bool {
					return containsAny(s, "use-after-free")
				})
			}},
		{Emoji: "🗝️", Name: "Locksmith", Description: "Fixed a locking issue.",
			Predicate: func(bug BugInfo, totalBugs int) bool {
				return checkBugAndCommits(bug.LowerTitle, bug.LowerCommitTitles, lockBadgeRegex.MatchString)
			}},
		{Emoji: "🕯️", Name: "Exorcist", Description: "Fixed a hung task or zombie process.",
			Predicate: func(bug BugInfo, totalBugs int) bool {
				return checkBugAndCommits(bug.LowerTitle, bug.LowerCommitTitles, func(s string) bool {
					return containsAny(s, "hung task", "task hung", "zombie")
				})
			}},
		{Emoji: "🕳️", Name: "Abyss Walker", Description: "Fixed a NULL pointer dereference.",
			Predicate: func(bug BugInfo, totalBugs int) bool {
				return checkBugAndCommits(bug.LowerTitle, bug.LowerCommitTitles, func(s string) bool {
					return containsAny(s, "null-ptr-deref", "null pointer")
				})
			}},
		{Emoji: "⚗️", Name: "Alchemist", Description: "Fixed an uninitialized value bug.",
			Predicate: func(bug BugInfo, totalBugs int) bool {
				return checkBugAndCommits(bug.LowerTitle, bug.LowerCommitTitles, func(s string) bool {
					return containsAny(s, "uninit", "kmsan")
				})
			}},
		{Emoji: "🪓", Name: "Executioner", Description: "Fixed a double free bug.",
			Predicate: func(bug BugInfo, totalBugs int) bool {
				return checkBugAndCommits(bug.LowerTitle, bug.LowerCommitTitles, func(s string) bool {
					return containsAny(s, "double-free", "double free")
				})
			}},
	}
}

// ScaleAttribute calculates the scaled attribute value on an RPG-like scale [3, 30] using a logarithmic function.
func ScaleAttribute(rawVal, base, factor float64) int {
	attr := int(base + factor*math.Log10(rawVal))
	if attr < 3 {
		return 3
	}
	if attr > 30 {
		return 30
	}
	return attr
}

// CalculateLevel calculates the player's level based on their total XP/score.
func CalculateLevel(score int) int {
	xpLeft := score
	level := 1
	for {
		req := 1000
		if level >= 50 {
			req = 1000 + (level-49)*500
		}
		if xpLeft >= req {
			xpLeft -= req
			level++
		} else {
			break
		}
	}
	return level
}

func GetClassNameByEmoji(emoji string) string {
	if emoji == "⚔️" {
		return "Warrior"
	}
	for _, c := range classLookup {
		if c.Emoji == emoji {
			return c.Name
		}
	}
	return ""
}

type KingdomTier struct {
	Tier      string
	TierEmoji string
	TierDesc  string
}

func GetKingdomTier(score int) KingdomTier {
	if score < 50000 {
		return KingdomTier{"Outpost", "⛺", "0 - 50k XP"}
	} else if score < 150000 {
		return KingdomTier{"Barony", "🏘️", "50k - 150k XP"}
	} else if score < 500000 {
		return KingdomTier{"Duchy", "🏛️", "150k - 500k XP"}
	} else if score < 1000000 {
		return KingdomTier{"Kingdom", "🏰", "500k - 1M XP"}
	} else {
		return KingdomTier{"Empire", "👑", "1M+ XP"}
	}
}

type FormattedGuild struct {
	Emoji string
	Name  string
}

func GetKingdomGuilds(guildCounts map[string]int) []FormattedGuild {
	type guildData struct {
		Emoji string
		Name  string
		Count int
	}
	var guildList []guildData
	for emoji, count := range guildCounts {
		name := GetClassNameByEmoji(emoji)
		if count > 1 {
			name += "s"
		}
		guildList = append(guildList, guildData{Emoji: emoji, Name: name, Count: count})
	}

	sort.Slice(guildList, func(i, j int) bool {
		if guildList[i].Count == guildList[j].Count {
			return guildList[i].Name < guildList[j].Name
		}
		return guildList[i].Count > guildList[j].Count
	})

	var guilds []FormattedGuild
	for _, g := range guildList {
		guilds = append(guilds, FormattedGuild{Emoji: g.Emoji, Name: fmt.Sprintf("%d %s", g.Count, g.Name)})
	}
	return guilds
}
