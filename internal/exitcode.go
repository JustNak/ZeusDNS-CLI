// Package internal holds cross-cutting helpers: exit codes and logging.
package internal

// Process exit codes. These are stable — scripts and callers may rely on
// specific non-zero values. Patterns:
//
//	 0  ExitSuccess   — normal completion
//	 1  ExitMisconfig — config load/validation failure
//	 2  ExitService   — service install/start/stop/recovery failure
//	 3  ExitBadArg    — bad command-line argument or value
//	 4  ExitNetwork   — network/upstream/DNS failure (port conflict, unreachable)
//	70  ExitFailure   — generic/unexpected internal failure (EX_SOFTWARE)
//130  ExitCancelled — user-initiated cancellation (SIGINT+128)
const (
	ExitSuccess   = 0   // finished, no errors
	ExitMisconfig = 1   // config load/validate failures
	ExitService   = 2   // service install/start/stop/recovery failures
	ExitBadArg    = 3   // bad command-line argument or value (moved from 2)
	ExitNetwork   = 4   // upstream/DNS/network failures (port conflict, unreachable)
	ExitFailure   = 70  // generic/unexpected internal failure (EX_SOFTWARE)
	ExitCancelled = 130 // user-initiated cancellation (SIGINT+128)
)
