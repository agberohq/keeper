package main

// These variables are set at build time via -ldflags.
// Default values are used when building without the Makefile or CI.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)
