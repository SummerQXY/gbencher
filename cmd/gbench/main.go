// gbench is a scan-only GCP/GKE CIS benchmark scanner.
package main

import (
	"os"

	"github.com/SummerQXY/gbencher/internal/cli"
)

func main() {
	os.Exit(cli.Execute(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, os.Environ()))
}
