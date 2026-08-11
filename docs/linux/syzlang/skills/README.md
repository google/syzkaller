# Syzlang Subsystem Skills (Linux)

This directory contains component and subsystem-specific knowledge and
constraints for LLM agents generating or fixing Linux syzlang programs.

## Format

Each skill must be a Markdown (`.md`) file starting with standard YAML
frontmatter defining `name` and `description`:

```markdown
---
name: kvm
description: KVM Virtualization and Guest Constraints (x86/amd64 Focus)
---

# KVM Virtualization and Guest Constraints (x86/amd64 Focus)

... instructions ...
```

## How Agents Use Skills

In AFlow, available skills are dynamically listed in `SkillsPrompt(osTarget)`.
Agents can inspect any skill using `read-syz-spec` with either a short name
(`kvm.md` or `skills/kvm.md`) or full relative path
(`docs/linux/syzlang/skills/kvm.md`).
