// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package glance

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/google/syzkaller/pkg/clangtool"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/osutil"
)

type Orchestrator struct {
	KernelSrc string
	KernelObj string
	CacheDir  string

	mu        sync.Mutex
	flightMap map[string]*sync.Cond
}

func NewOrchestrator(kernelSrc, kernelObj, cacheDir string) *Orchestrator {
	return &Orchestrator{
		KernelSrc: kernelSrc,
		KernelObj: kernelObj,
		CacheDir:  cacheDir,
	}
}

func (orc *Orchestrator) Summarize(ctx context.Context, filePath string, force bool) (string, error) {
	absPath := filepath.Join(orc.KernelSrc, filePath)
	if !osutil.IsExist(absPath) {
		return "", fmt.Errorf("file %v does not exist", absPath)
	}

	sourceHash := orc.getSourceHash(absPath)
	summaryPath := filepath.Join(orc.CacheDir, filePath+".md")

	// 1. Check Cache
	if !force {
		if data, err := os.ReadFile(summaryPath); err == nil {
			content := string(data)
			if strings.Contains(content, sourceHash) {
				// If it's a DEMO summary but we now have a key, bypass cache.
				if strings.Contains(content, "[DEMO]") && os.Getenv("GOOGLE_API_KEY") != "" {
					fmt.Fprintf(os.Stderr, "Bypassing cached [DEMO] result as GOOGLE_API_KEY is now present.\n")
				} else {
					return content, nil
				}
			}
		}
	}

	// 2. Flight Map (Coalesce concurrent requests)
	orc.mu.Lock()
	if orc.flightMap == nil {
		orc.flightMap = make(map[string]*sync.Cond)
	}
	if cond, ok := orc.flightMap[filePath]; ok {
		cond.Wait()
		orc.mu.Unlock()
		return orc.Summarize(ctx, filePath, force) // Retry from cache
	}
	cond := sync.NewCond(&orc.mu)
	orc.flightMap[filePath] = cond
	orc.mu.Unlock()

	defer func() {
		orc.mu.Lock()
		delete(orc.flightMap, filePath)
		cond.Broadcast()
		orc.mu.Unlock()
	}()

	// 3. Run Static Analyzer on this specific file
	cfg := &clangtool.Config{
		Tool:       "glance",
		KernelSrc:  orc.KernelSrc,
		KernelObj:  orc.KernelObj,
		Files:      []string{filePath},
		DebugTrace: os.Stderr,
	}

	out, missingFiles, err := clangtool.Run[Output, *Output](cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: static analyzer failed for %s: %v\nProceeding without static analysis data.\n", filePath, err)
		// Fallback: create an empty output with MissingCompileCommand set.
		out = &Output{
			MissingCompileCommand: filePath,
		}
	}

	// 4. Prepare Context for LLM
	rawCode, err := os.ReadFile(absPath)
	if err != nil {
		return "", err
	}

	// Assemble JITI (symbols from headers)
	var jiti strings.Builder
	for _, sym := range out.Symbols {
		if sym.File != filePath {
			fmt.Fprintf(&jiti, "--- %s (%s) ---\n%s\n\n", sym.Name, sym.Kind, sym.Definition)
		}
	}

	// Flagged functions
	var flagged strings.Builder
	for _, fn := range out.Functions {
		if fn.Complexity >= 10 || len(fn.LocksUsed) > 0 {
			fmt.Fprintf(&flagged, "- %s (Complexity: %d, Locks: %v)\n", fn.Name, fn.Complexity, fn.LocksUsed)
		}
	}

	// Prepare inputs for the agent (using the template placeholders)
	inputs := map[string]any{
		"File":    filePath,
		"Headers": jiti.String(),
		"Flagged": flagged.String(),
		"Source":  string(rawCode),
	}

	if out.MissingCompileCommand != "" || slices.Contains(missingFiles, filePath) {
		fmt.Fprintf(os.Stderr, "WARNING: %s is missing from compile_commands.json. Static analysis checks (exported symbols, JITI) will be incomplete.\n", filePath)
		// Ensure we flag it in the output struct so it reaches the frontmatter logic
		out.MissingCompileCommand = filePath
	}

	var description string
	var summaryBody string
	if os.Getenv("GOOGLE_API_KEY") == "" {
		description = "Demo description."
		summaryBody = fmt.Sprintf("# [DEMO] Summary of %s\n\n## JITI Symbols extracted:\n%s\n## Flagged Functions:\n%s\n\n> [!NOTE]\n> Real LLM summary requires GOOGLE_API_KEY.",
			filePath, jiti.String(), flagged.String())
	} else {
		// Real LLM call using aflow.Flow
		cache, err := aflow.NewCache(filepath.Join(orc.CacheDir, ".llm"), 10<<30) // 10GB
		if err != nil {
			return "", fmt.Errorf("failed to create aflow cache: %w", err)
		}

		orc.ensureFlows()

		onEvent := func(span *trajectory.Span) error { return nil }

		// We map our inputs to the agent's prompt template expectations.
		// aflow.LLMAgent uses {{.Field}} syntax.
		inputs["Includes"] = strings.Join(out.Includes, ", ")
		res, err := glanceFlow.Execute(ctx, "", orc.CacheDir, inputs, cache, onEvent)
		if err != nil {
			return "", fmt.Errorf("LLM execution failed: %w", err)
		}
		summaryBody = res["Summary"].(string)

		// Strip any frontmatter if the LLM generated it, because we add our own authoritative one.
		// But first extract the description!
		if strings.HasPrefix(strings.TrimSpace(summaryBody), "---") {
			parts := strings.SplitN(summaryBody, "---", 3)
			if len(parts) >= 3 {
				frontmatter := parts[1]
				if idx := strings.Index(frontmatter, "description: "); idx != -1 {
					rest := frontmatter[idx+len("description: "):]
					if endIdx := strings.Index(rest, "\n"); endIdx != -1 {
						description = strings.TrimSpace(rest[:endIdx])
						description = strings.Trim(description, `"'`)
					}
				}
				summaryBody = strings.TrimSpace(parts[2])
			}
		}
	}

	var providedAPIs []string
	for _, fn := range out.Functions {
		if fn.IsExported && fn.File == filePath {
			providedAPIs = append(providedAPIs, fn.Name)
		}
	}
	sort.Strings(providedAPIs)
	providedAPIsStr := fmt.Sprintf("[%s]", strings.Join(providedAPIs, ", "))

	configs := extractConfigs(rawCode)
	configsStr := fmt.Sprintf("[%s]", strings.Join(configs, ", "))

	includesStr := fmt.Sprintf("[%s]", strings.Join(out.Includes, ", "))

	missingCompileCommand := ""
	if out.MissingCompileCommand != "" {
		missingCompileCommand = "\nmissing_compile_command: true"
	}

	summary := fmt.Sprintf("---\npath: %s\nsource_hash: %s\nincludes: %s\nprovided_apis: %s\ndescription: \"%s\"\nreferenced_configs: %s%s\n---\n\n%s", filePath, sourceHash, includesStr, providedAPIsStr, description, configsStr, missingCompileCommand, summaryBody)

	// 6. Store in Cache
	os.MkdirAll(filepath.Dir(summaryPath), 0755)
	os.WriteFile(summaryPath, []byte(summary), 0644)

	return summary, nil
}

func (orc *Orchestrator) SummarizeDirectory(ctx context.Context, dirPath string, force bool) (string, error) {
	absPath := filepath.Join(orc.KernelSrc, dirPath)
	entries, err := os.ReadDir(absPath)
	if err != nil {
		return "", err
	}

	var fileNames []string
	var subDirs []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".c") {
			fileNames = append(fileNames, entry.Name())
		} else if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
			subDirs = append(subDirs, entry.Name())
		}
	}
	sort.Strings(fileNames)
	sort.Strings(subDirs)

	var summaries strings.Builder
	var exportedAPIs strings.Builder
	var fileDescriptions strings.Builder

	for _, fileName := range fileNames {
		subPath := filepath.Join(dirPath, fileName)
		summary, err := orc.Summarize(ctx, subPath, force)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to summarize %s: %v\n", subPath, err)
			continue
		}

		// Strip frontmatter from individual summaries for the aggregate prompt
		if strings.HasPrefix(strings.TrimSpace(summary), "---") {
			parts := strings.SplitN(summary, "---", 3)
			if len(parts) >= 3 {
				summary = strings.TrimSpace(parts[2])

				// Extract provided_apis from frontmatter
				frontmatter := parts[1]
				if idx := strings.Index(frontmatter, "provided_apis: ["); idx != -1 {
					rest := frontmatter[idx+len("provided_apis: ["):]
					if endIdx := strings.Index(rest, "]"); endIdx != -1 {
						apis := rest[:endIdx]
						if len(apis) > 0 {
							fmt.Fprintf(&exportedAPIs, "## %s\n- %s\n\n", fileName, strings.ReplaceAll(apis, ", ", "\n- "))
						}
					}
				}

				// Extract description from frontmatter
				desc := ""
				if idx := strings.Index(frontmatter, "description: "); idx != -1 {
					rest := frontmatter[idx+len("description: "):]
					if endIdx := strings.Index(rest, "\n"); endIdx != -1 {
						desc = strings.TrimSpace(rest[:endIdx])
						desc = strings.Trim(desc, `"'`) // Remove quotes if present
					}
				}
				if desc != "" {
					fmt.Fprintf(&fileDescriptions, "- **%s**: %s\n", fileName, desc)
				} else {
					fmt.Fprintf(&fileDescriptions, "- **%s**: (No description available)\n", fileName)
				}
			}
		} else {
			fmt.Fprintf(&fileDescriptions, "- **%s**: (No description available)\n", fileName)
		}

		fmt.Fprintf(&summaries, "## File: %s\n%s\n\n", fileName, summary)
	}

	for _, subDir := range subDirs {
		// Attempt to read existing summary for subdir if available
		desc := "(Subdirectory)"
		subReadme := filepath.Join(orc.CacheDir, dirPath, subDir, "README.md")
		if data, err := os.ReadFile(subReadme); err == nil {
			content := string(data)
			if strings.HasPrefix(content, "---\n") {
				parts := strings.SplitN(content, "---", 3)
				if len(parts) >= 3 {
					frontmatter := parts[1]
					if idx := strings.Index(frontmatter, "description: "); idx != -1 {
						rest := frontmatter[idx+len("description: "):]
						if endIdx := strings.Index(rest, "\n"); endIdx != -1 {
							extracted := strings.TrimSpace(rest[:endIdx])
							extracted = strings.Trim(extracted, `"'`)
							if extracted != "" {
								desc = extracted
							}
						}
					}
				}
			} else {
				desc = "(Subdirectory - Summarized)"
			}
		}
		fmt.Fprintf(&fileDescriptions, "- **%s/**: %s\n", subDir, desc)
	}

	if summaries.Len() == 0 {
		return "", fmt.Errorf("no C files found or summarized in %s", dirPath)
	}

	// Calculate a hash for the directory based on the file content hashes, OR just assume if files change their summaries change?
	// Strictly speaking, we should hash the summaries.
	dirHash := hash.String([]byte(summaries.String()))
	summaryPath := filepath.Join(orc.CacheDir, dirPath, "README.md")

	// Check Cache
	if !force {
		if data, err := os.ReadFile(summaryPath); err == nil {
			content := string(data)
			if strings.Contains(content, dirHash) {
				if strings.Contains(content, "[DEMO]") && os.Getenv("GOOGLE_API_KEY") != "" {
					// Bypass
				} else {
					return content, nil
				}
			}
		}
	}

	var summaryBody string
	var description string
	if os.Getenv("GOOGLE_API_KEY") == "" {
		summaryBody = fmt.Sprintf("# [DEMO] Directory Summary of %s\n\n### File Summaries\n%s\n\n> [!NOTE]\n> Real LLM summary requires GOOGLE_API_KEY.", dirPath, summaries.String())
		description = "Demo directory description."
	} else {
		cache, err := aflow.NewCache(filepath.Join(orc.CacheDir, ".llm"), 10<<30)
		if err != nil {
			return "", err
		}

		orc.ensureFlows()

		inputs := map[string]any{
			"Dir":              dirPath,
			"FileSummaries":    summaries.String(),
			"ExportedAPIs":     exportedAPIs.String(),
			"FileDescriptions": fileDescriptions.String(),
		}

		res, err := glanceDirFlow.Execute(ctx, "", orc.CacheDir, inputs, cache, func(s *trajectory.Span) error { return nil })
		if err != nil {
			return "", fmt.Errorf("LLM execution failed: %w", err)
		}
		summaryBody = res["Summary"].(string)

		if strings.HasPrefix(strings.TrimSpace(summaryBody), "---") {
			parts := strings.SplitN(summaryBody, "---", 3)
			if len(parts) >= 3 {
				frontmatter := parts[1]
				if idx := strings.Index(frontmatter, "description: "); idx != -1 {
					rest := frontmatter[idx+len("description: "):]
					if endIdx := strings.Index(rest, "\n"); endIdx != -1 {
						description = strings.TrimSpace(rest[:endIdx])
						description = strings.Trim(description, `"'`)
					}
				}
				summaryBody = strings.TrimSpace(parts[2])
			}
		}
	}

	// Append the file descriptions to the summary
	summaryBody += "\n\n### Files\n" + fileDescriptions.String()

	summary := fmt.Sprintf("---\npath: %s\nsource_hash: %s\ndescription: \"%s\"\n---\n\n%s", dirPath, dirHash, description, summaryBody)
	os.MkdirAll(filepath.Dir(summaryPath), 0755)
	os.WriteFile(summaryPath, []byte(summary), 0644)
	return summary, nil
}

func (orc *Orchestrator) ensureFlows() {
	registerOnce.Do(func() {
		agent := &aflow.LLMAgent{
			Name:        "glance-summarizer",
			Model:       aflow.GoodBalancedModel,
			Reply:       "Summary",
			TaskType:    aflow.FormalReasoningTask,
			Instruction: SystemInstruction,
			Prompt:      PromptTemplate,
		}
		glanceFlow = &aflow.Flow{
			Name: "glance",
			Root: agent,
		}
		aflow.Register[GlanceInputs, GlanceOutputs](ai.WorkflowType("glance"), "glance summarization", glanceFlow)

		agentDir := &aflow.LLMAgent{
			Name:        "glance-dir-summarizer",
			Model:       aflow.GoodBalancedModel,
			Reply:       "Summary",
			TaskType:    aflow.FormalReasoningTask,
			Instruction: DirectorySystemInstruction,
			Prompt:      DirectoryPromptTemplate,
		}
		glanceDirFlow = &aflow.Flow{
			Name: "glance-dir",
			Root: agentDir,
		}
		aflow.Register[DirSummaryInputs, DirSummaryOutputs](ai.WorkflowType("glance-dir"), "glance directory summarization", glanceDirFlow)
	})
}

type GlanceInputs struct {
	File     string
	Source   string
	Headers  string
	Flagged  string
	Includes string
}

type GlanceOutputs struct {
	Summary string
}

var (
	registerOnce  sync.Once
	glanceFlow    *aflow.Flow
	glanceDirFlow *aflow.Flow
)

func (orc *Orchestrator) getSourceHash(file string) string {
	data, _ := os.ReadFile(file)
	return hash.String(data)
}

func extractConfigs(source []byte) []string {
	// Match CONFIG_ followed by alphanumeric characters and underscores
	re := regexp.MustCompile(`\bCONFIG_[A-Z0-9_]+\b`)
	matches := re.FindAll(source, -1)

	unique := make(map[string]bool)
	for _, m := range matches {
		unique[string(m)] = true
	}

	var result []string
	for cfg := range unique {
		result = append(result, cfg)
	}
	sort.Strings(result)
	return result
}
