package config

import (
	_ "embed"
	"fmt"
	"os"
	"regexp"

	"github.com/gustavo-iniguez-goya/decloaker/data"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/config/patterns"
	"gopkg.in/yaml.v3"
)

var defaultPatternsYAML = data.SuspiciousPatterns

// Common proc status field names
const (
	ProcStatusPPid    = "PPid"
	ProcStatusKthread = "Kthread"
	ProcStatusUid     = "Uid"
	ProcStatusGid     = "Gid"
	ProcStatusVmSize  = "VmSize"
	ProcStatusThreads = "Threads"
)

type UIDRule struct {
	UID         int               `yaml:"uid"`
	CommPattern string            `yaml:"comm_pattern"`
	Severity    patterns.Severity `yaml:"severity"`
	Description string            `yaml:"description"`
	re          *regexp.Regexp
}

// MatchComm returns true when the comm name is suspicious for this UID
// (i.e. it does NOT match the expected-comm pattern).
func (r *UIDRule) MatchComm(comm string) bool { return r.re != nil && !r.re.MatchString(comm) }

// fileDetectionConfig uses pointer fields so we can distinguish
// "key absent in file" (nil → keep default) from "key set to zero value".
type fileDetectionConfig struct {
	BindMounts *struct {
		Enabled *bool   `yaml:"enabled"`
		Source  *string `yaml:"source"`
	} `yaml:"bind_mounts"`
	Ebpf *struct {
		Enabled *bool `yaml:"enabled"`
	} `yaml:"ebpf_compare"`
	Cgroups *struct {
		Enabled    *bool   `yaml:"enabled"`
		Root       *string `yaml:"root"`
		FileSuffix *string `yaml:"file_suffix"`
	} `yaml:"cgroups"`
	BruteForce *struct {
		Enabled *bool `yaml:"enabled"`
		PidMax  *int  `yaml:"pid_max"`
		PidMin  *int  `yaml:"pid_min"`
	} `yaml:"brute_force"`
	DefaultHiddenPaths *struct {
		Files   []string `yaml:"files"`
		Content []string `yaml:"content"`
	} `yaml:"default_hidden_paths"`
}

// rawConfig is what we unmarshal from YAML (both the embedded default and any
// user-supplied override file). ProcessPatterns uses *[]T so we can tell
// whether a list was provided at all.
type rawConfig struct {
	Version   int                 `yaml:"version"`
	Detection fileDetectionConfig `yaml:"detection"`
	Patterns  struct {
		Process    *[]patterns.Pattern `yaml:"process"`
		Connection *[]patterns.Pattern `yaml:"connection"`
		File       *[]patterns.Pattern `yaml:"file"`
	} `yaml:"patterns"`
	Allowlist *struct {
		ExePaths  []string `yaml:"exe_paths"`
		CommNames []string `yaml:"comm_names"`
		PIDs      []int    `yaml:"pids"`
	} `yaml:"allowlist"`
}

// PatternsConfig is the fully-resolved, compiled configuration.
type PatternsConfig struct {
	Version   int
	Detection struct {
		BindMounts struct {
			Enabled bool
			Source  string
		}
		Ebpf struct {
			Enabled bool
		}
		Cgroups struct {
			Enabled    bool
			Root       string
			FileSuffix string
		}
		BruteForce struct {
			Enabled bool
			PidMax  int
			PidMin  int
		}
		DefaultHiddenPaths struct {
			Files   []string
			Content []string
		}
	}

	// Legacy pattern fields (for backward compatibility)
	ExePaths []patterns.PatternRule
	Comm     []patterns.PatternRule
	Cmdline  []patterns.PatternRule
	UID      []UIDRule

	// New recursive patterns
	ProcessPatterns    []patterns.Pattern
	ConnectionPatterns []patterns.Pattern
	FilePatterns       []patterns.Pattern

	Allowlist struct {
		ExePaths  []string
		CommNames []string
		PIDs      []int
	}

	// pre-compiled allowlist regexes
	allowExeRe  []*regexp.Regexp
	allowCommRe []*regexp.Regexp
}

// New builds a PatternsConfig from the embedded default (data/suspis.yaml).
// If patternsFile is non-empty the file is loaded and merged on top:
//
// - detection.* : per-field override; absent keys keep the default.
// - process_patterns.* : full list replace; if the key is present in the
//   file the built-in list is discarded entirely.
// - allowlist.* : union; file entries are appended and deduplicated.
func New(patternsFile string) (*PatternsConfig, error) {

	if patternsFile != "" {
		data, err := os.ReadFile(patternsFile)
		if err != nil {
			return nil, fmt.Errorf("reading patterns file %q: %w", patternsFile, err)
		}
		base, err := parseRaw(data, patternsFile)
		if err != nil {
			return nil, err
		}
		//base = mergeRaw(base, override)
		return compile(base)
	}

	base, err := parseRaw(defaultPatternsYAML, "<embedded default>")
	if err != nil {
		return nil, err
	}
	return compile(base)
}

// WriteDefault writes the embedded default configuration to dst so users have
// a ready-to-edit starting point:
//
//	decloaker scan suspicious-procs --dump-patterns > /etc/decloaker/suspis.yaml
func WriteDefault(dst string) error {
	return os.WriteFile(dst, defaultPatternsYAML, 0o644)
}

func parseRaw(data []byte, source string) (*rawConfig, error) {
	var rc rawConfig
	if err := yaml.Unmarshal(data, &rc); err != nil {
		return nil, fmt.Errorf("parsing patterns from %s: %w", source, err)
	}
	return &rc, nil
}

func mergeRaw(base, override *rawConfig) *rawConfig {
	// --- detection: field-level override (nil pointer = not set in file) ---
	if bm := override.Detection.BindMounts; bm != nil {
		if base.Detection.BindMounts == nil {
			base.Detection.BindMounts = &struct {
				Enabled *bool   `yaml:"enabled"`
				Source  *string `yaml:"source"`
			}{}
		}
		if bm.Enabled != nil {
			base.Detection.BindMounts.Enabled = bm.Enabled
		}
		if bm.Source != nil {
			base.Detection.BindMounts.Source = bm.Source
		}
	}

	if eb := override.Detection.Ebpf; eb != nil {
		if base.Detection.Ebpf == nil {
			base.Detection.Ebpf = &struct {
				Enabled *bool `yaml:"enabled"`
			}{}
		}
		if eb.Enabled != nil {
			base.Detection.Ebpf.Enabled = eb.Enabled
		}
	}

	if cg := override.Detection.Cgroups; cg != nil {
		if base.Detection.Cgroups == nil {
			base.Detection.Cgroups = &struct {
				Enabled    *bool   `yaml:"enabled"`
				Root       *string `yaml:"root"`
				FileSuffix *string `yaml:"file_suffix"`
			}{}
		}
		if cg.Enabled != nil {
			base.Detection.Cgroups.Enabled = cg.Enabled
		}
		if cg.Root != nil {
			base.Detection.Cgroups.Root = cg.Root
		}
		if cg.FileSuffix != nil {
			base.Detection.Cgroups.FileSuffix = cg.FileSuffix
		}
	}

	if bf := override.Detection.BruteForce; bf != nil {
		if base.Detection.BruteForce == nil {
			base.Detection.BruteForce = &struct {
				Enabled *bool `yaml:"enabled"`
				PidMax  *int  `yaml:"pid_max"`
				PidMin  *int  `yaml:"pid_min"`
			}{}
		}
		if bf.Enabled != nil {
			base.Detection.BruteForce.Enabled = bf.Enabled
		}
		if bf.PidMax != nil {
			base.Detection.BruteForce.PidMax = bf.PidMax
		}
		if bf.PidMin != nil {
			base.Detection.BruteForce.PidMin = bf.PidMin
		}
	}

	if bf := override.Detection.DefaultHiddenPaths; bf != nil {
		if base.Detection.DefaultHiddenPaths == nil {
			base.Detection.DefaultHiddenPaths = &struct {
				Files   []string `yaml:"files"`
				Content []string `yaml:"content"`
			}{}
		}
		if bf.Files != nil {
			base.Detection.DefaultHiddenPaths.Files = bf.Files
		}
		if bf.Content != nil {
			base.Detection.DefaultHiddenPaths.Content = bf.Content
		}
	}

	// New recursive patterns
	if override.Patterns.Process != nil {
		base.Patterns.Process = override.Patterns.Process
	}
	if override.Patterns.Connection != nil {
		base.Patterns.Connection = override.Patterns.Connection
	}
	if override.Patterns.File != nil {
		base.Patterns.File = override.Patterns.File
	}

	// --- allowlist: union ---
	if al := override.Allowlist; al != nil {
		if base.Allowlist == nil {
			base.Allowlist = al
		} else {
			base.Allowlist.ExePaths = dedupStrings(base.Allowlist.ExePaths, al.ExePaths)
			base.Allowlist.CommNames = dedupStrings(base.Allowlist.CommNames, al.CommNames)
			base.Allowlist.PIDs = dedupInts(base.Allowlist.PIDs, al.PIDs)
		}
	}

	return base
}

func compile(rc *rawConfig) (*PatternsConfig, error) {
	cfg := &PatternsConfig{Version: rc.Version}

	// detection scalars
	if bm := rc.Detection.BindMounts; bm != nil {
		if bm.Enabled != nil {
			cfg.Detection.BindMounts.Enabled = *bm.Enabled
		}
		if bm.Source != nil {
			cfg.Detection.BindMounts.Source = *bm.Source
		}
	}

	if eb := rc.Detection.Ebpf; eb != nil {
		if eb.Enabled != nil {
			cfg.Detection.Ebpf.Enabled = *eb.Enabled
		}
	}

	if cg := rc.Detection.Cgroups; cg != nil {
		if cg.Enabled != nil {
			cfg.Detection.Cgroups.Enabled = *cg.Enabled
		}
		if cg.Root != nil {
			cfg.Detection.Cgroups.Root = *cg.Root
		}
		if cg.FileSuffix != nil {
			cfg.Detection.Cgroups.FileSuffix = *cg.FileSuffix
		}
	}

	if bf := rc.Detection.BruteForce; bf != nil {
		if bf.Enabled != nil {
			cfg.Detection.BruteForce.Enabled = *bf.Enabled
		}
		if bf.PidMax != nil {
			cfg.Detection.BruteForce.PidMax = *bf.PidMax
		}
		if bf.PidMin != nil {
			cfg.Detection.BruteForce.PidMin = *bf.PidMin
		}
	}

	if bf := rc.Detection.DefaultHiddenPaths; bf != nil {
		if bf.Files != nil {
			cfg.Detection.DefaultHiddenPaths.Files = bf.Files
		}
		if bf.Content != nil {
			cfg.Detection.DefaultHiddenPaths.Content = bf.Content
		}
	}

	var err error
	if cfg.ProcessPatterns, err = compilePatterns(rc.Patterns.Process); err != nil {
		return nil, fmt.Errorf("process patterns: %w", err)
	}
	if cfg.ConnectionPatterns, err = compilePatterns(rc.Patterns.Connection); err != nil {
		return nil, fmt.Errorf("connection patterns: %w", err)
	}
	if cfg.FilePatterns, err = compilePatterns(rc.Patterns.File); err != nil {
		return nil, fmt.Errorf("file patterns: %w", err)
	}

	// allowlist
	if al := rc.Allowlist; al != nil {
		cfg.Allowlist.ExePaths = al.ExePaths
		cfg.Allowlist.CommNames = al.CommNames
		cfg.Allowlist.PIDs = al.PIDs
	}

	for _, p := range cfg.Allowlist.ExePaths {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("allowlist exe_path %q: %w", p, err)
		}
		cfg.allowExeRe = append(cfg.allowExeRe, re)
	}

	for _, c := range cfg.Allowlist.CommNames {
		re, err := regexp.Compile(`^` + regexp.QuoteMeta(c) + `$`)
		if err != nil {
			return nil, fmt.Errorf("allowlist comm_name %q: %w", c, err)
		}
		cfg.allowCommRe = append(cfg.allowCommRe, re)
	}

	return cfg, nil
}

func compileRules(rules *[]patterns.PatternRule) ([]patterns.PatternRule, error) {
	if rules == nil {
		return nil, nil
	}
	out := make([]patterns.PatternRule, len(*rules))
	for i, r := range *rules {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("pattern %q: %w", r.Pattern, err)
		}
		out[i] = r
		out[i].Re = re
	}
	return out, nil
}

func compileUIDRules(rules *[]UIDRule) ([]UIDRule, error) {
	if rules == nil {
		return nil, nil
	}
	out := make([]UIDRule, len(*rules))
	for i, r := range *rules {
		re, err := regexp.Compile(r.CommPattern)
		if err != nil {
			return nil, fmt.Errorf("uid rule comm_pattern %q: %w", r.CommPattern, err)
		}
		out[i] = r
		out[i].re = re
	}
	return out, nil
}

func compilePatterns(ptList *[]patterns.Pattern) ([]patterns.Pattern, error) {
	if ptList == nil {
		return nil, nil
	}
	out := make([]patterns.Pattern, len(*ptList))
	for i, p := range *ptList {
		if err := p.Compile(); err != nil {
			return nil, fmt.Errorf("pattern index %d: %w", i, err)
		}
		out[i] = p
	}
	return out, nil
}

func (cfg *PatternsConfig) IsAllowedExe(exe string) bool {
	for _, re := range cfg.allowExeRe {
		if re.MatchString(exe) {
			return true
		}
	}
	return false
}

func (cfg *PatternsConfig) IsAllowedComm(comm string) bool {
	for _, re := range cfg.allowCommRe {
		if re.MatchString(comm) {
			return true
		}
	}
	return false
}

func (cfg *PatternsConfig) IsAllowedPID(pid int) bool {
	for _, p := range cfg.Allowlist.PIDs {
		if p == pid {
			return true
		}
	}
	return false
}

// New recursive pattern matching methods
func (cfg *PatternsConfig) MatchProcess(provider patterns.DataProvider) *patterns.Pattern {
	for i := range cfg.ProcessPatterns {
		if cfg.ProcessPatterns[i].Match(provider) {
			return &cfg.ProcessPatterns[i]
		}
	}
	return nil
}

func (cfg *PatternsConfig) MatchConnection(provider patterns.DataProvider) *patterns.Pattern {
	for i := range cfg.ConnectionPatterns {
		if cfg.ConnectionPatterns[i].Match(provider) {
			return &cfg.ConnectionPatterns[i]
		}
	}
	return nil
}

func (cfg *PatternsConfig) MatchFile(provider patterns.DataProvider) *patterns.Pattern {
	for i := range cfg.FilePatterns {
		if cfg.FilePatterns[i].Match(provider) {
			return &cfg.FilePatterns[i]
		}
	}
	return nil
}

func dedupStrings(base, extra []string) []string {
	seen := make(map[string]struct{}, len(base))
	for _, s := range base {
		seen[s] = struct{}{}
	}
	out := append([]string(nil), base...)
	for _, s := range extra {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

func dedupInts(base, extra []int) []int {
	seen := make(map[int]struct{}, len(base))
	for _, n := range base {
		seen[n] = struct{}{}
	}
	out := append([]int(nil), base...)
	for _, n := range extra {
		if _, ok := seen[n]; !ok {
			seen[n] = struct{}{}
			out = append(out, n)
		}
	}
	return out
}
