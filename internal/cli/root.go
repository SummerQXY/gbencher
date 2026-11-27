// Package cli holds the command tree of gbench. Execute builds every command from scratch on
// each call so that tests can run it many times in a single process without state leaking.
// stdin and env are accepted for completeness; lint does not read them.
package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

// Execute runs a gbench command with args, writing output to stdout and stderr. stdin and env
// are accepted for completeness; lint does not read them. Execute never calls os.Exit and
// writes only to the writers it is given.
func Execute(args []string, stdin io.Reader, stdout, stderr io.Writer, env []string) int {
	root := &cobra.Command{
		Use:               "gbench",
		SilenceUsage:      true,
		SilenceErrors:     true,
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetIn(stdin)

	root.AddCommand(rulesCmd(stdout, stderr))
	root.AddCommand(scanCmd(stdin, stdout, stderr, env))
	root.AddCommand(collectCmd(stdout, stderr, env))
	root.AddCommand(authCmd(stdout, stderr, env))
	root.AddCommand(kubeCredentialCmd(stdout, stderr, env))
	root.AddCommand(versionCmd(stdout))

	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		if e, ok := err.(*exitError); ok {
			return e.code
		}
		fmt.Fprintln(stderr, "gbench:", err.Error())
		return 2
	}
	return 0
}

// rulesCmd builds the rules command and its subcommands. A group command without a RunE
// would treat an unknown verb as a request for help and succeed; the explicit NoArgs check and
// RunE that delegates to cmd.Help make cobra reject unknown subcommands with an error, which
// Execute maps to exit 2.
func rulesCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Work with rule files",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(rulesLintCmd(stdout, stderr))
	cmd.AddCommand(rulesListCmd(stdout, stderr))
	cmd.AddCommand(rulesShowCmd(stdout))
	cmd.AddCommand(rulesTestCmd(stdout, stderr))
	return cmd
}

// exitError is an error that carries an exit code. Execute returns its code instead of 2.
type exitError struct {
	code int
}

func (e *exitError) Error() string { return "" }
