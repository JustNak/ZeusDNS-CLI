package tui

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/huh"

	"github.com/JustNak/ZeusDNS-CLI/dns"
)

// WizardResult is what the first-run wizard collects.
type WizardResult struct {
	Install  bool
	Primary  string
	Fallback string // may be empty
}

// RunWizard walks the user through first-run setup. It returns immediately
// with Install=false if the user declines. Resolver fields are validated live:
// a non-responding resolver is reported and re-prompted.
func RunWizard() (*WizardResult, error) {
	res := &WizardResult{Install: true}

	confirm := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title("Would you like to install?").
				Description("Installs ZeusDNS as a Windows service and sets 127.0.0.1 as your system DNS.").
				Value(&res.Install).
				Affirmative("Yes").
				Negative("No"),
		).Title("--- Zeus_DNS-CLI ---"),
	)
	if err := confirm.Run(); err != nil {
		return nil, err
	}
	if !res.Install {
		return res, nil
	}

	resolverForm := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Provide your DNS Resolver: DoH/DoT").
				Placeholder("https://dns.controld.com/p2").
				Value(&res.Primary).
				Validate(validateResolver(true)),
			huh.NewInput().
				Title("Fallback DNS Resolver (Enter empty is fine)").
				Placeholder("tls://dns.adguard.com").
				Value(&res.Fallback).
				Validate(validateResolver(false)),
		).Title("--- Zeus_DNS-CLI ---"),
	)
	if err := resolverForm.Run(); err != nil {
		return nil, err
	}
	res.Primary = strings.TrimSpace(res.Primary)
	res.Fallback = strings.TrimSpace(res.Fallback)
	return res, nil
}

// validateResolver returns a huh validator that parses and health-checks the
// entered resolver. When required is false, an empty value passes.
func validateResolver(required bool) func(string) error {
	return func(s string) error {
		s = strings.TrimSpace(s)
		if s == "" {
			if required {
				return fmt.Errorf("resolver is required")
			}
			return nil
		}
		u, err := dns.ParseUpstream(s)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), dns.CheckTimeout)
		defer cancel()
		if err := u.Check(ctx); err != nil {
			return fmt.Errorf("resolver didn't respond: %v", err)
		}
		return nil
	}
}
