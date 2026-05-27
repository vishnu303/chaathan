package main

import (
	"fmt"
	"os"

	"github.com/vishnu303/chaathan/cli"
	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/paths"
)

func main() {
	// Resolve ~/. chaathan home directory once at startup
	if err := paths.Init(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Ensure database is properly closed on exit (flushes WAL, releases locks)
	defer database.Close()

	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
