package model

import (
	"fmt"
	"strings"

	networkingv1alpha3 "istio.io/client-go/pkg/apis/networking/v1alpha3"
	securityv1beta1 "istio.io/client-go/pkg/apis/security/v1beta1"
	corev1 "k8s.io/api/core/v1"
)

// Namespace is a Kubernetes namespace together with the metadata checks use.
type Namespace struct {
	Name        string
	Labels      map[string]string
	Annotations map[string]string
}

// Snapshot holds all Istio and k8s resources fetched from one namespace.
type Snapshot struct {
	Namespace string

	// NamespaceLabels and NamespaceAnnotations describe the namespace itself.
	// They are nil when the collector was not allowed to read the Namespace object.
	NamespaceLabels      map[string]string
	NamespaceAnnotations map[string]string

	VirtualServices  []*networkingv1alpha3.VirtualService
	DestinationRules []*networkingv1alpha3.DestinationRule
	Gateways         []*networkingv1alpha3.Gateway
	EnvoyFilters     []*networkingv1alpha3.EnvoyFilter
	PeerAuths        []*securityv1beta1.PeerAuthentication
	SystemPeerAuths  []*securityv1beta1.PeerAuthentication // mesh-wide PAs from istio-system
	Pods             []corev1.Pod
}

// Finding is a single issue detected by a check.
type Finding struct {
	Severity  Severity
	Check     string
	Resource  string
	Namespace string
	Message   string
	Fix       string
}

// Severity ranks findings. Lower values are more severe.
type Severity int

const (
	SeverityCritical Severity = iota
	SeverityHigh
	SeverityMedium
	SeverityLow
)

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "CRITICAL"
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityLow:
		return "LOW"
	}
	return "UNKNOWN"
}

// AtLeast reports whether s is as severe as, or more severe than, threshold.
func (s Severity) AtLeast(threshold Severity) bool {
	return s <= threshold
}

// ParseSeverity converts a case-insensitive severity name to a Severity.
func ParseSeverity(name string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "critical":
		return SeverityCritical, nil
	case "high":
		return SeverityHigh, nil
	case "medium":
		return SeverityMedium, nil
	case "low":
		return SeverityLow, nil
	}
	return 0, fmt.Errorf("unknown severity %q (want critical, high, medium or low)", name)
}
