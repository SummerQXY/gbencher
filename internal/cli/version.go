package cli

import (
	"fmt"
	"io"
	"sort"

	"github.com/SummerQXY/gbencher/internal/rule"
	"github.com/spf13/cobra"
)

var toolVersion = "dev"

func versionCmd(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print gbench and embedded ruleset versions",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			set, err := rule.LoadEmbedded()
			if err != nil {
				return err
			}
			fmt.Fprintf(stdout, "gbench %s\nschema_version: 1.1\nruleset_hash: %s\n", toolVersion, set.Hash)
			baselines := make(map[string]bool)
			for _, current := range set.Rules {
				if current != nil {
					baselines[current.Benchmark.ID+"@"+current.Benchmark.Version] = true
				}
			}
			list := make([]string, 0, len(baselines))
			for baseline := range baselines {
				list = append(list, baseline)
			}
			sort.Strings(list)
			for _, baseline := range list {
				fmt.Fprintf(stdout, "baseline: %s\n", baseline)
			}
			return nil
		},
	}
}
