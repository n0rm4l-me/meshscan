// Command meshscan audits Istio service mesh configuration.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/n0rm4l-me/meshscan/internal/cli"
	"github.com/n0rm4l-me/meshscan/internal/version"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Execute(ctx, os.Args[1:], cli.Env{
		StdoutIsTerminal: isTerminal(os.Stdout),
		Version:          version.Summary(),
	})
	stop() // os.Exit skips deferred calls
	os.Exit(code)
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
