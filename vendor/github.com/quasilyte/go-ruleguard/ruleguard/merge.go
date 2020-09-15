package ruleguard

func mergeRuleSets(toMerge []*GoRuleSet) *GoRuleSet {
	out := &GoRuleSet{
		local:     &scopedGoRuleSet{},
		universal: &scopedGoRuleSet{},
	}

	for _, x := range toMerge {
		out.local = appendScopedRuleSet(out.local, x.local)
		out.universal = appendScopedRuleSet(out.universal, x.universal)
	}

	return out
}

func appendScopedRuleSet(dst, src *scopedGoRuleSet) *scopedGoRuleSet {
	dst.uncategorized = append(dst.uncategorized, src.uncategorized...)
	for cat, rules := range src.rulesByCategory {
		dst.rulesByCategory[cat] = append(dst.rulesByCategory[cat], rules...)
		dst.categorizedNum += len(rules)
	}
	return dst
}
