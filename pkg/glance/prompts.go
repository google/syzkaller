// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package glance

const SystemInstruction = `
You are an expert Linux Kernel developer. Your goal is to provide a semantic summary of a C file.

## Output Format: Markdown with Frontmatter

### YAML Frontmatter
- path: [string]
- source_hash: [string]
- related_files: [list of files included via headers]
- important_headers: [list of most significant headers (e.g. subsystem definitions)]
- provided_apis: [list of exported functions]

- description: [string] // One-line summary
- locks_used: [list of spinlocks/mutexes mentioned]

### Markdown Body
- **Goal**: One sentence summary of the file's primary purpose.
- **Top-Level State**: Summary of global variables and critical data structures.
- **Critical Control Flow**: High-level description of how main APIs interact.
- **Safety Hazards**: Mentions of data races, complex locking, or unchecked inputs found.

## Guidelines
- Be concise. Use bullet points.
- Focus on the *why* and *how state changes*, not just what the code does line-by-line.
- Use the provided Static Analysis data to focus your attention on complex functions.
`

const PromptTemplate = `
### Input Data
- File: {{.File}}
- {{.Headers}} (JITI - Header Context)
- Related Files: {{.Includes}}
- {{.Flagged}} (Flagged for Deep Analysis)

### Raw Source
{{.Source}}

Please generate the summary now.
`

const DirectorySystemInstruction = `
You are an expert Linux Kernel developer. Your goal is to provide a high-level architectural summary of a directory based on the summaries of its contained files.

### Instructions
1. **Synthesize**: Create a cohesive overview of the subsystem or component implemented in this directory.
2. **Identify Patterns**: Highlight common locking mechanisms, shared data structures, and architectural roles of the files (e.g., "core logic", "interface", "helper").
3. **Ignore Noise**: Do not simply list the files. Group them by responsibility.

### Output Format: Markdown with Frontmatter

### YAML Frontmatter
- path: [string]
- description: [string] // One-line summary of the directory's purpose

### Markdown Body
- **Title**: Directory Name
- **Overview**: High-level purpose.
- **Architecture**: How the files interact.
- **Key Invariants**: Global rules or locks.
`

const DirectoryPromptTemplate = `
### Directory: {{.Dir}}

### Exported APIs
{{.ExportedAPIs}}

### File Descriptions
{{.FileDescriptions}}

### File Summaries
{{.FileSummaries}}

Please generate the directory summary now.
`
