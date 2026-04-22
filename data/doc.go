package data

import (
	_ "embed"
)

//go:embed suspicious-patterns.yaml
// this line must go here
var SuspiciousPatterns []byte
