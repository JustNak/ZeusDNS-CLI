//go:build windows
// +build windows

// Package service manages the ZeusDNS Windows service lifecycle (install,
// uninstall, start, stop, restart, status) and provides the in-service
// execution loop used when the binary is launched by the Service Control
// Manager.
package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/JustNak/ZeusDNS-CLI/config"
)

// IsWindowsService reports whether the current process was launched by the
// Service Control Manager. Used by main to decide between the CLI and the
// service entry point.
func IsWindowsService() bool {
	is, err := svc.IsWindowsService()
	return err == nil && is
}

func connect() (*mgr.Mgr, error) { return mgr.Connect() }

// Install creates the service pointing at exePath with automatic start,
// then configures SCM recovery actions so the service restarts automatically
// after a crash (the SCM restart acts as the watchdog).
// Extra args (e.g. "-c", configPath) are appended to the service binPath;
// CreateService escapes each one correctly. Pass JUST the exe path as
// exePath, not a pre-quoted command line.
func Install(exePath string, args ...string) error {
	m, err := connect()
	if err != nil {
		return fmt.Errorf("connect SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.CreateService(config.ServiceName, exePath, mgr.Config{
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
		DisplayName:  config.ServiceName,
		Description:  config.ServiceDesc,
	}, args...)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()

	// Configure SCM recovery: restart the service on 1st, 2nd, and any
	// subsequent failure. The reset-period means the failure count is
	// reset to zero after 60s of steady operation, so a one-time glitch
	// won't keep the service in a permanent restart loop.
	recoveryActions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 0},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
	}
	const resetPeriodSecs = 60
	if err := s.SetRecoveryActions(recoveryActions, resetPeriodSecs); err != nil {
		return fmt.Errorf("set recovery actions: %w", err)
	}
	return nil
}

// Uninstall stops (best-effort) and deletes the service.
func Uninstall() error {
	m, err := connect()
	if err != nil {
		return fmt.Errorf("connect SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(config.ServiceName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer s.Close()

	if err := stopAndWait(s); err != nil {
		return fmt.Errorf("stop service: %w (refusing to delete a running service; stop it manually and retry)", err)
	}
	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}
	return nil
}

// Start launches the installed service.
func Start() error {
	m, err := connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(config.ServiceName)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Start()
}

// Stop stops the running service.
func Stop() error {
	m, err := connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(config.ServiceName)
	if err != nil {
		return err
	}
	defer s.Close()
	return stopAndWait(s)
}

// Restart stops and starts the service.
func Restart() error {
	if err := Stop(); err != nil && !isNotRunning(err) {
		return err
	}
	return Start()
}

// Status returns a human-readable state string.
func Status() (string, error) {
	m, err := connect()
	if err != nil {
		return "", err
	}
	defer m.Disconnect()
	s, err := m.OpenService(config.ServiceName)
	if err != nil {
		return "", err
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return "", err
	}
	return stateString(st.State), nil
}

func stopAndWait(s *mgr.Service) error {
	st, err := s.Query()
	if err == nil && st.State == svc.Stopped {
		return nil
	}
	if _, err := s.Control(svc.Stop); err != nil {
		return err
	}
	for i := 0; i < 40; i++ {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == svc.Stopped {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for service to stop")
}

func stateString(s svc.State) string {
	switch s {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "start-pending"
	case svc.StopPending:
		return "stop-pending"
	case svc.Running:
		return "running"
	case svc.ContinuePending:
		return "continue-pending"
	case svc.PausePending:
		return "pause-pending"
	case svc.Paused:
		return "paused"
	default:
		return "unknown"
	}
}

func isNotRunning(err error) bool {
	// Tolerate only the genuine "service not running" / "does not exist" errors.
	if err == nil {
		return false
	}
	var errno windows.Errno
	if errors.As(err, &errno) {
		return errno == windows.ERROR_SERVICE_NOT_ACTIVE || errno == windows.ERROR_SERVICE_DOES_NOT_EXIST
	}
	return false
}

// Run is the service entry point. It is called only when the process is
// launched by the SCM. run is invoked in a goroutine with a context that is
// canceled when the SCM requests stop or shutdown; run should perform its own
// startup (system DNS, WFP, DNS server) and honor ctx for cleanup.
func Run(name string, run func(ctx context.Context) error) error {
	return svc.Run(name, &handler{run: run})
}

type handler struct {
	run func(ctx context.Context) error
}

func (h *handler) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	changes <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("run panic: %v", r)
			}
		}()
		done <- h.run(ctx)
	}()

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				changes <- svc.Status{State: svc.Stopped}
				return false, 0
			}
		case err := <-done:
			// run exited on its own; surface any error to the SCM.
			changes <- svc.Status{State: svc.StopPending}
			cancel()
			changes <- svc.Status{State: svc.Stopped}
			if err != nil {
				return false, 1
			}
			return false, 0
		}
	}
}
