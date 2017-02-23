package service

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/cenkalti/backoff"
	"github.com/coreos/go-iptables/iptables"
	logging "github.com/op/go-logging"
	"github.com/pkg/errors"
)

type ServiceConfig struct {
}

type ServiceDependencies struct {
	Logger *logging.Logger
}

type Service struct {
	ServiceConfig
	ServiceDependencies

	client    *iptables.IPTables
	chainName string
}

const (
	filterTable = "filter"
)

// NewService creates a new Service from given config & dependencies
func NewService(config ServiceConfig, deps ServiceDependencies) (*Service, error) {
	client, err := iptables.New()
	if err != nil {
		return nil, maskAny(err)
	}

	// Create random ID
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return nil, maskAny(err)
	}
	id := hex.EncodeToString(b)

	s := &Service{
		ServiceConfig:       config,
		ServiceDependencies: deps,
		client:              client,
		chainName:           fmt.Sprintf("NETBLK-%s", id),
	}
	return s, nil
}

// Initialize initializes an iptables chain for this service.
func (s *Service) Initialize() error {
	op := func() error {
		if err := s.client.ClearChain(filterTable, s.chainName); err != nil {
			return maskAny(err)
		}
		if err := s.client.Append(filterTable, s.chainName, "-j", "RETURN"); err != nil {
			return maskAny(err)
		}
		if err := s.client.Insert(filterTable, "INPUT", 1, "-j", s.chainName); err != nil {
			return maskAny(err)
		}
		if err := s.client.Insert(filterTable, "FORWARD", 1, "-j", s.chainName); err != nil {
			return maskAny(err)
		}
		if err := s.client.Insert(filterTable, "OUTPUT", 1, "-j", s.chainName); err != nil {
			return maskAny(err)
		}
		return nil
	}
	if err := backoff.Retry(op, backoff.NewExponentialBackOff()); err != nil {
		return maskAny(err)
	}
	return nil
}

// Cleanup removes all generated iptables chain & rules made by this service.
func (s *Service) Cleanup() error {
	if err := s.client.Delete(filterTable, "INPUT", "-j", s.chainName); err != nil {
		s.Logger.Warningf("Failed to remove INPUT chain rule: %v", err)
	}
	if err := s.client.Delete(filterTable, "FORWARD", "-j", s.chainName); err != nil {
		s.Logger.Warningf("Failed to remove FORWARD chain rule: %v", err)
	}
	if err := s.client.Delete(filterTable, "OUTPUT", "-j", s.chainName); err != nil {
		s.Logger.Warningf("Failed to remove OUTPUT chain rule: %v", err)
	}
	if err := s.client.ClearChain(filterTable, s.chainName); err != nil {
		s.Logger.Warningf("Failed to clear '%s' chain: %v", s.chainName, err)
	}
	if err := s.client.DeleteChain(filterTable, s.chainName); err != nil {
		s.Logger.Warningf("Failed to remove '%s' chain: %v", s.chainName, err)
	}
	return nil
}

// RejectTCP actively denies all traffic on the given TCP port
func (s *Service) RejectTCP(port int) error {
	op := func() error {
		ruleBuilder := func(action string) []string { return createPortRuleSpec(port, action) }
		if err := s.removeRuleSpecs(ruleBuilder, "DROP"); err != nil {
			return maskAny(err)
		}
		ruleSpec := createPortRuleSpec(port, "REJECT")
		if found, err := s.client.Exists(filterTable, s.chainName, ruleSpec...); err != nil {
			s.Logger.Errorf("Failed to check existance of rulespec %q: %v", ruleSpec, err)
			return maskAny(err)
		} else if !found {
			s.Logger.Infof("Denying traffic to TCP port %d", port)
			if err := s.client.Insert(filterTable, s.chainName, 1, ruleSpec...); err != nil {
				s.Logger.Errorf("Failed to deny traffic to TCP port %d: %v", port, err)
				return maskAny(err)
			}
		}
		return nil
	}
	if err := backoff.Retry(op, backoff.NewExponentialBackOff()); err != nil {
		return maskAny(err)
	}
	return nil
}

// DropTCP silently denies all traffic on the given TCP port
func (s *Service) DropTCP(port int) error {
	op := func() error {
		ruleBuilder := func(action string) []string { return createPortRuleSpec(port, action) }
		if err := s.removeRuleSpecs(ruleBuilder, "REJECT"); err != nil {
			return maskAny(err)
		}
		ruleSpec := createPortRuleSpec(port, "DROP")
		s.Logger.Infof("Denying traffic to TCP port %d", port)
		if found, err := s.client.Exists(filterTable, s.chainName, ruleSpec...); err != nil {
			s.Logger.Errorf("Failed to check existance of rulespec %q: %v", ruleSpec, err)
			return maskAny(err)
		} else if !found {
			if err := s.client.Insert(filterTable, s.chainName, 1, ruleSpec...); err != nil {
				s.Logger.Errorf("Failed to deny traffic to TCP port %d: %v", port, err)
				return maskAny(err)
			}
		}
		return nil
	}
	if err := backoff.Retry(op, backoff.NewExponentialBackOff()); err != nil {
		return maskAny(err)
	}
	return nil
}

// AcceptTCP allow all traffic on the given TCP port
func (s *Service) AcceptTCP(port int) error {
	op := func() error {
		s.Logger.Infof("Accepting traffic to TCP port %d", port)
		ruleBuilder := func(action string) []string { return createPortRuleSpec(port, action) }
		if err := s.removeRuleSpecs(ruleBuilder, "REJECT", "DROP"); err != nil {
			return maskAny(err)
		}
		return nil
	}
	if err := backoff.Retry(op, backoff.NewExponentialBackOff()); err != nil {
		return maskAny(err)
	}
	return nil
}

// RejectAllFrom actively denies all traffic coming from the given IP address on the given interface
func (s *Service) RejectAllFrom(ip, intf string) error {
	op := func() error {
		ruleBuilder := func(action string) []string { return createSourceRuleSpec(ip, intf, action) }
		if err := s.removeRuleSpecs(ruleBuilder, "DROP"); err != nil {
			return maskAny(err)
		}
		ruleSpec := createSourceRuleSpec(ip, intf, "REJECT")
		if found, err := s.client.Exists(filterTable, s.chainName, ruleSpec...); err != nil {
			s.Logger.Errorf("Failed to check existance of rulespec %q: %v", ruleSpec, err)
			return maskAny(err)
		} else if !found {
			s.Logger.Infof("Denying traffic from IP %s on %s", ip, intf)
			if err := s.client.Insert(filterTable, s.chainName, 1, ruleSpec...); err != nil {
				s.Logger.Errorf("Failed to deny traffic from IP %s on %s: %v", ip, intf, err)
				return maskAny(err)
			}
		}
		return nil
	}
	if err := backoff.Retry(op, backoff.NewExponentialBackOff()); err != nil {
		return maskAny(err)
	}
	return nil
}

// DropAllFrom silently denies all traffic coming from the given IP address on the given interface
func (s *Service) DropAllFrom(ip, intf string) error {
	op := func() error {
		ruleBuilder := func(action string) []string { return createSourceRuleSpec(ip, intf, action) }
		if err := s.removeRuleSpecs(ruleBuilder, "REJECT"); err != nil {
			return maskAny(err)
		}
		ruleSpec := createSourceRuleSpec(ip, intf, "DROP")
		s.Logger.Infof("Denying traffic from IP %s on %s", ip, intf)
		if found, err := s.client.Exists(filterTable, s.chainName, ruleSpec...); err != nil {
			s.Logger.Errorf("Failed to check existance of rulespec %q: %v", ruleSpec, err)
			return maskAny(err)
		} else if !found {
			if err := s.client.Insert(filterTable, s.chainName, 1, ruleSpec...); err != nil {
				s.Logger.Errorf("Failed to deny traffic from IP %s on %s: %v", ip, intf, err)
				return maskAny(err)
			}
		}
		return nil
	}
	if err := backoff.Retry(op, backoff.NewExponentialBackOff()); err != nil {
		return maskAny(err)
	}
	return nil
}

// AcceptAllFrom allow all traffic coming from the given IP address on the given interface
func (s *Service) AcceptAllFrom(ip, intf string) error {
	op := func() error {
		s.Logger.Infof("Accepting traffic from IP %s on %s", ip, intf)
		ruleBuilder := func(action string) []string { return createSourceRuleSpec(ip, intf, action) }
		if err := s.removeRuleSpecs(ruleBuilder, "REJECT", "DROP"); err != nil {
			return maskAny(err)
		}
		return nil
	}
	if err := backoff.Retry(op, backoff.NewExponentialBackOff()); err != nil {
		return maskAny(err)
	}
	return nil
}

// Rules returns a list of all rules injected by this service.
func (s *Service) Rules() ([]string, error) {
	var result []string
	op := func() error {
		list, err := s.client.List(filterTable, s.chainName)
		if err != nil {
			return maskAny(err)
		}
		result = list
		return nil
	}
	if err := backoff.Retry(op, backoff.NewExponentialBackOff()); err != nil {
		return nil, maskAny(err)
	}
	return result, nil
}

// removeRuleSpecs removes all rules with given actions to given port.
func (s *Service) removeRuleSpecs(ruleBuilder func(action string) []string, actions ...string) error {
	for _, action := range actions {
		ruleSpec := ruleBuilder(action)
		if found, err := s.client.Exists(filterTable, s.chainName, ruleSpec...); err != nil {
			s.Logger.Errorf("Failed to check existance of rulespec %q: %v", ruleSpec, err)
			return maskAny(err)
		} else if found {
			if err := s.client.Delete(filterTable, s.chainName, ruleSpec...); err != nil {
				s.Logger.Errorf("Failed to remove rulespec %q: %v", ruleSpec, err)
				return maskAny(err)
			}
		}
	}
	return nil
}

func createPortRuleSpec(port int, action string) []string {
	return []string{
		"-p", "tcp",
		"-m", "tcp", "--dport", strconv.Itoa(port),
		"-j", action,
	}
}

func createSourceRuleSpec(ip, intf string, action string) []string {
	var spec []string
	if ip != "" {
		spec = append(spec, "-s", fmt.Sprintf("%s/32", ip))
	}
	if intf != "" {
		spec = append(spec, "-i", intf)
	}
	return append(spec,
		"-j", action,
	)
}

func isExitCodeError(err error, exitCode int) bool {
	eerr, ok := errors.Cause(err).(*iptables.Error)
	return ok && eerr.ExitStatus() == exitCode
}
