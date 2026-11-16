package checks

import (
	"strconv"

	networkingv1alpha3 "istio.io/client-go/pkg/apis/networking/v1alpha3"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

// CheckOutlierDetection flags DestinationRules that have no outlier detection configured.
// Without it, unhealthy pods continue to receive traffic until the service fully fails.
//
// A rule passes when the top-level traffic policy configures outlier detection,
// or when every subset carries its own (a subset policy replaces the top-level one).
func CheckOutlierDetection(snap *model.Snapshot) []model.Finding {
	var findings []model.Finding
	for _, dr := range snap.DestinationRules {
		if hasOutlierDetection(dr) {
			continue
		}
		findings = append(findings, model.Finding{
			Severity:  model.SeverityHigh,
			Check:     NameOutlierDetection,
			Resource:  "DestinationRule/" + dr.Name,
			Namespace: dr.Namespace,
			Message:   "no outlier detection; unhealthy endpoints stay in load balancer rotation",
			Fix:       "add spec.trafficPolicy.outlierDetection: {consecutive5xxErrors: 5, interval: 30s, baseEjectionTime: 30s}",
		})
	}
	return findings
}

func hasOutlierDetection(dr *networkingv1alpha3.DestinationRule) bool {
	if dr.Spec.GetTrafficPolicy().GetOutlierDetection() != nil {
		return true
	}
	subsets := dr.Spec.GetSubsets()
	if len(subsets) == 0 {
		return false
	}
	for _, s := range subsets {
		if s.GetTrafficPolicy().GetOutlierDetection() == nil {
			return false
		}
	}
	return true
}

// CheckRetryWithoutTimeout flags VirtualService HTTP rules that configure retries
// with attempts > 0 but set no request timeout. Retries amplify inflight requests;
// without a timeout the total retry budget is unbounded. A timeout of 0s disables
// the timeout in Istio, so it counts as no timeout.
func CheckRetryWithoutTimeout(snap *model.Snapshot) []model.Finding {
	var findings []model.Finding
	for _, vs := range snap.VirtualServices {
		for i, rule := range vs.Spec.GetHttp() {
			retries := rule.GetRetries()
			if retries == nil || retries.GetAttempts() == 0 {
				continue
			}
			if rule.GetTimeout() != nil && rule.GetTimeout().AsDuration() > 0 {
				continue
			}
			findings = append(findings, model.Finding{
				Severity:  model.SeverityMedium,
				Check:     NameRetryNoTimeout,
				Resource:  "VirtualService/" + vs.Name,
				Namespace: vs.Namespace,
				Message:   "http rule[" + strconv.Itoa(i) + "] has retries=" + strconv.Itoa(int(retries.GetAttempts())) + " but no timeout; unbounded retry amplification possible",
				Fix:       "add timeout: 10s (or appropriate value) to cap total retry budget",
			})
		}
	}
	return findings
}
