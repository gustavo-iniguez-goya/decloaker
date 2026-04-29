package data

import (
	_ "embed"
)

//go:embed default-config.yaml
// this line must go here
var DefaultConfig []byte
