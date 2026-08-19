package model

import (
	networkingv1alpha3 "istio.io/client-go/pkg/apis/networking/v1alpha3"
	securityv1beta1 "istio.io/client-go/pkg/apis/security/v1beta1"
	corev1 "k8s.io/api/core/v1"
)

// Snapshot holds all Istio and k8s resources fetched from one namespace.
type Snapshot struct {
	Namespace        string
	VirtualServices  []*networkingv1alpha3.VirtualService
	DestinationRules []*networkingv1alpha3.DestinationRule
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
