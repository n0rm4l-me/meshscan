package version

import (
	"runtime/debug"
	"testing"
)

func TestSummary(t *testing.T) {
	buildInfo := func(mainVersion string, settings ...debug.BuildSetting) *debug.BuildInfo {
		return &debug.BuildInfo{Main: debug.Module{Version: mainVersion}, Settings: settings}
	}
	vcs := []debug.BuildSetting{
		{Key: "vcs.revision", Value: "0123456789abcdef0123"},
		{Key: "vcs.time", Value: "2026-01-02T03:04:05Z"},
	}

	tests := []struct {
		name                  string
		version, commit, date string
		bi                    *debug.BuildInfo
		want                  string
	}{
		{
			name:    "linker values win",
			version: "1.2.3", commit: "abc1234", date: "2026-03-04T00:00:00Z",
			bi:   buildInfo("v9.9.9", vcs...),
			want: "1.2.3 (commit abc1234, built 2026-03-04T00:00:00Z, go1.test)",
		},
		{
			name:    "go install pkg@version supplies the version",
			version: "dev",
			bi:      buildInfo("v1.4.0"),
			want:    "v1.4.0 (go1.test)",
		},
		{
			name:    "go build in a git checkout supplies commit and time",
			version: "dev",
			bi:      buildInfo("(devel)", vcs...),
			want:    "dev (commit 0123456789ab, built 2026-01-02T03:04:05Z, go1.test)",
		},
		{
			name:    "no build info",
			version: "dev",
			bi:      nil,
			want:    "dev (go1.test)",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := summary(tc.version, tc.commit, tc.date, tc.bi, "go1.test"); got != tc.want {
				t.Errorf("summary = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestShortAndSummaryDefaultToDev(t *testing.T) {
	// Under `go test` nothing is injected and the main module is "(devel)".
	if got := Short(); got != "dev" {
		t.Errorf("Short() = %q, want dev", got)
	}
	if got := Summary(); got == "" {
		t.Error("Summary() is empty")
	}
}
