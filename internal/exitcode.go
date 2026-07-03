// Package internal holds cross-cutting helpers: exit codes and logging.
package internal

// Process exit codes. Match the AdGuard DNS CLI convention so callers and
// scripts can rely on a stable contract.
const (
	ExitSuccess   = 0 // finished, no errors
	ExitMisconfig = 1 // internal error or misconfiguration
	ExitBadArg    = 2 // bad command-line argument or value
)
