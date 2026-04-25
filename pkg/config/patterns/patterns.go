package patterns

import (
	_ "embed"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

const (
	DataRegex   = "regex"
	DataNetwork = "network"
	DataString  = "string"
	DataInt     = "int"
	DataBool    = "bool"
)

const (
	OpEqual       = "=="
	OpEqualStr    = "equals"
	OpNotEqual    = "!="
	OpNotEqualStr = "not_equals"
	OpGt          = ">"
	OpGtStr       = "gt"
	OpGte         = ">="
	OpGteStr      = "gte"
	OpLt          = "<"
	OpLte         = "<="
	OpLtStr       = "lt"
	OpLteStr      = "lte"
	OpContains    = "contains"
	OpPrefix      = "prefix"
	OpSuffix      = "suffix"
)

// DataProvider abstracts any data source (process, connection, file, etc.)
// that can be matched against patterns
type DataProvider interface {
	Get(field string) (interface{}, bool)
}

// Pattern represents a recursive pattern matching rule
type Pattern struct {
	Type        string     `yaml:"type"`        // Field name: "cmdline", "ppid", "src_ip", etc.
	DataType    string     `yaml:"data_type"`   // Type of value: "string", "regex", "int", "network", "bool"
	Operand     string     `yaml:"operand"`     // Comparison: "==", OpNotEqual, OpGt, OpLt, OpGte, OpLte, "contains", "prefix", "suffix"
	Data        string     `yaml:"data"`        // The value to match against
	Severity    Severity   `yaml:"severity"`    // Severity level
	Description string     `yaml:"description"` // Human-readable description
	Patterns    []*Pattern `yaml:"patterns"`    // Recursive sub-patterns (AND logic)

	// Pre-compiled matchers (populated during Compile())
	compiledRegex   *regexp.Regexp
	compiledNetwork *net.IPNet
	compiledInt     int64
	compiledBool    bool
}

// Compile pre-processes the pattern for efficient matching
func (p *Pattern) Compile() error {
	switch p.DataType {
	case DataRegex:
		re, err := regexp.Compile(p.Data)
		if err != nil {
			return fmt.Errorf("invalid regex in pattern %s: %w", p.Type, err)
		}
		p.compiledRegex = re

	case DataNetwork:
		_, network, err := net.ParseCIDR(p.Data)
		if err != nil {
			return fmt.Errorf("invalid network in pattern %s: %w", p.Type, err)
		}
		p.compiledNetwork = network

	case DataInt:
		val, err := strconv.ParseInt(p.Data, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid int in pattern %s: %w", p.Type, err)
		}
		p.compiledInt = val

	case DataBool:
		val, err := strconv.ParseBool(p.Data)
		if err != nil {
			return fmt.Errorf("invalid bool in pattern %s: %w", p.Type, err)
		}
		p.compiledBool = val

	case DataString:
		// No compilation needed

	default:
		return fmt.Errorf("unknown data_type: %s", p.DataType)
	}

	// Recursively compile sub-patterns
	for _, subPattern := range p.Patterns {
		if err := subPattern.Compile(); err != nil {
			return err
		}
	}

	return nil
}

// Match is the universal recursive matching function
func (p *Pattern) Match(provider DataProvider) bool {
	// Get the data for this pattern's field
	value, exists := provider.Get(p.Type)
	if !exists {
		return false
	}

	// Match based on the data_type and operand
	result := p.matchValue(value)

	if !result {
		return false
	}

	// Recursively check all sub-patterns (AND logic)
	for _, subPattern := range p.Patterns {
		if !subPattern.Match(provider) {
			return false
		}
	}

	return true
}

func (p *Pattern) matchValue(value interface{}) bool {
	switch p.DataType {
	case DataRegex:
		return p.matchRegex(value)
	case DataInt:
		return p.matchInt(value)
	case DataNetwork:
		return p.matchNetwork(value)
	case DataBool:
		return p.matchBool(value)
	default:
		// default type string
		return p.matchString(value)
	}
}

func (p *Pattern) matchString(value interface{}) bool {
	str, ok := value.(string)
	if !ok {
		return false
	}

	switch p.Operand {
	case OpNotEqual, OpNotEqualStr:
		return str != p.Data
	case OpContains:
		return strings.Contains(str, p.Data)
	//case OpNotContains:
	//	return !strings.Contains(str, p.Data)
	case OpPrefix:
		return strings.HasPrefix(str, p.Data)
	case OpSuffix:
		return strings.HasSuffix(str, p.Data)
	default:
		// assume equal operation
		return str == p.Data
	}
}

func (p *Pattern) matchRegex(value interface{}) bool {
	str, ok := value.(string)
	if !ok {
		return false
	}
	matched := p.compiledRegex.MatchString(str)

	switch p.Operand {
	case OpNotEqual, OpNotEqualStr:
		return !matched
	default:
		// assume equal
		return matched
	}
}

func (p *Pattern) matchInt(value interface{}) bool {
	var intVal int64

	switch v := value.(type) {
	case int:
		intVal = int64(v)
	case int32:
		intVal = int64(v)
	case int64:
		intVal = v
	case string:
		intStr, ok := value.(string)
		if !ok {
			return false
		}
		intV, err := strconv.Atoi(intStr)
		if err != nil {
			return false
		}
		intVal = int64(intV)
	default:
		return false
	}

	switch p.Operand {
	case OpNotEqual, OpNotEqualStr:
		return intVal != p.compiledInt
	case OpGt, OpGtStr:
		return intVal > p.compiledInt
	case OpLt, OpLtStr:
		return intVal < p.compiledInt
	case OpGte, OpGteStr:
		return intVal >= p.compiledInt
	case OpLte, OpLteStr:
		return intVal <= p.compiledInt
	default:
		// assume equal
		return intVal == p.compiledInt
	}
}

func (p *Pattern) matchNetwork(value interface{}) bool {
	var ip net.IP

	switch v := value.(type) {
	case string:
		ip = net.ParseIP(v)
	case net.IP:
		ip = v
	default:
		return false
	}

	if ip == nil {
		return false
	}

	contains := p.compiledNetwork.Contains(ip)

	switch p.Operand {
	case OpNotEqual, OpNotEqualStr:
		return !contains
	default:
		// assume equal
		return contains
	}
}

func (p *Pattern) matchBool(value interface{}) bool {
	boolVal, ok := value.(bool)
	if !ok {
		return false
	}

	switch p.Operand {
	case OpNotEqual, OpNotEqualStr:
		return boolVal != p.compiledBool
	default:
		// assume equal
		return boolVal == p.compiledBool
	}
}

// Legacy PatternRule for backward compatibility
type PatternRule struct {
	Pattern     string   `yaml:"pattern"`
	Severity    Severity `yaml:"severity"`
	Description string   `yaml:"description"`
	Re          *regexp.Regexp
}

func (r *PatternRule) Match(s string) bool { return r.Re != nil && r.Re.MatchString(s) }
