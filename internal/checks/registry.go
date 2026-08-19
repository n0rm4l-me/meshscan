package checks

import "github.com/n0rm4l-me/meshscan/internal/model"

// Check is a single audit rule.
type Check func(snap *model.Snapshot) []model.Finding

// All returns every registered check in order.
func All() []Check {
	return []Check{
		CheckMTLS,
		CheckEnvoyFilterScope,
		CheckSidecarCoverage,
		CheckDeadSubsets,
		CheckMissingGateway,
		CheckOutlierDetection,
		CheckMissingDR,
		CheckRetryWithoutTimeout,
	}
}
