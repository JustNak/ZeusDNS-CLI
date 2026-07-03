// Package cmd implements the user-facing command handlers (wizard, configure,
// service lifecycle, foreground run, update). main.go dispatches to these.
package cmd

// Version is the build version. Override at link time with:
//
//	go build -ldflags "-X github.com/JustNak/ZeusDNS-CLI/cmd.Version=1.0.0"
var Version = "dev"
