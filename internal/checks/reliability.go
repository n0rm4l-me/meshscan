package checks

import (
	"strconv"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

// CheckOutlierDetection flags DestinationRules that have no outlier detection configured.
// Without it, unhealthy pods continue to receive traffic until the service fully fails.
func CheckOutlierDetection(snap *model.Snapshot) []model.Finding {
	var findings []model.Finding
	for _, dr := range snap.DestinationRules {
		if dr.Spec.GetTrafficPolicy().GetOutlierDetection() == nil {
			findings = append(findings, model.Finding{
				Severity:  model.SeverityHigh,
				Check:     "outlier-detection",
				Resource:  "DestinationRule/" + dr.Name,
				Namespace: dr.Namespace,
				Message:   "no outlier detection; unhealthy endpoints stay in load balancer rotation",
				Fix:       "add spec.trafficPolicy.outlierDetection: {consecutive5xxErrors: 5, interval: 30s, baseEjectionTime: 30s}",
			})
		}
	}
	return findings
}
// CheckRetryWithoutTimeout flags VirtualService HTTP rules that configure retries
// with attempts > 0 but set no request timeout. Retries amplify inflight requests;
// without a timeout the total retry budget is unbounded.
func CheckRetryWithoutTimeout(snap *model.Snapshot) []model.Finding {
	var findings []model.Finding
	for _, vs := range snap.VirtualServices {
		for i, rule := range vs.Spec.GetHttp() {
			retries := rule.GetRetries()
			if retries == nil || retries.GetAttempts() == 0 {
				continue
			}
			if rule.GetTimeout() == nil {
				findings = append(findings, model.Finding{
					Severity:  model.SeverityMedium,
					Check:     "retry-without-timeout",
					Resource:  "VirtualService/" + vs.Name,
					Namespace: vs.Namespace,
					Message:   "http rule[" + strconv.Itoa(i) + "] has retries=" + strconv.Itoa(int(retries.GetAttempts())) + " but no timeout; unbounded retry amplification possible",
					Fix:       "add timeout: 10s (or appropriate value) to cap total retry budget",
				})
			}
		}
	}
	return findings
}

