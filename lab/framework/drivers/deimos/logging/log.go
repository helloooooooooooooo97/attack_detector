// Package logging is a minimal stand-in for DeimosC2's lib/logging used by
// the copied lib/crypto package (MIT).
package logging

import (
	"log"
	"os"
)

var (
	Logger      = log.New(os.Stdout, "deimos ", log.Ldate|log.Ltime)
	ErrorLogger = log.New(os.Stderr, "deimos-err ", log.Ldate|log.Ltime)
)
