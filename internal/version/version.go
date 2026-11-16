// Package version reports the build identity of the meshscan binary.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

// These are set at link time:
//
//	-ldflags "-X github.com/n0rm4l-me/meshscan/internal/version.Version=1.2.3 \
//	          -X github.com/n0rm4l-me/meshscan/internal/version.Commit=abc1234 \
//	          -X github.com/n0rm4l-me/meshscan/internal/version.Date=2026-01-02T03:04:05Z"
//
// When they are not set (go run, or go install pkg@version) the values are
// recovered from the module build information the Go toolchain embeds.
var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

const devVersion = "dev"

// Summary returns a one-line description such as
// "1.2.3 (commit abc1234, built 2026-01-02T03:04:05Z, go1.26.4)".
func Summary() string {
	bi, _ := debug.ReadBuildInfo()
	return summary(Version, Commit, Date, bi, runtime.Version())
}

// Short returns just the version number.
func Short() string {
	bi, _ := debug.ReadBuildInfo()
	v, _, _ := resolve(Version, Commit, Date, bi)
	return v
}

func summary(version, commit, date string, bi *debug.BuildInfo, goVersion string) string {
	v, c, d := resolve(version, commit, date, bi)
	var parts []string
	if c != "" {
		parts = append(parts, "commit "+c)
	}
	if d != "" {
		parts = append(parts, "built "+d)
	}
	parts = append(parts, goVersion)
	return fmt.Sprintf("%s (%s)", v, strings.Join(parts, ", "))
}

// resolve fills in whatever the linker did not provide from the embedded build info.
func resolve(version, commit, date string, bi *debug.BuildInfo) (v, c, d string) {
	v, c, d = version, commit, date
	if bi == nil {
		return v, c, d
	}
	if v == devVersion && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		v = bi.Main.Version
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			if c == "" {
				c = s.Value
				if len(c) > 12 {
					c = c[:12]
				}
			}
		case "vcs.time":
			if d == "" {
				d = s.Value
			}
		}
	}
	return v, c, d
}
