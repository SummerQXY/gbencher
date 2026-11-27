package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/SummerQXY/gbencher/internal/rule"
	"github.com/SummerQXY/gbencher/rules"
	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"
)

func rulesShowCmd(stdout io.Writer) *cobra.Command {
	project := ""
	cmd := &cobra.Command{
		Use:   "show <id>",
		Short: "Show a rule and its collection commands",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			set, err := rule.LoadEmbedded()
			if err != nil {
				return err
			}
			current, ok := set.Get(args[0])
			if !ok {
				return fmt.Errorf("unknown rule %q", args[0])
			}
			verification, err := rule.LoadVerification()
			if err != nil {
				return err
			}
			level := verification.Rules[current.ID]
			if level == "" {
				level = rule.VerificationNone
			}
			source, err := rules.FS.ReadFile(current.SourceFile)
			if err != nil {
				return err
			}
			var document map[string]any
			if err := yaml.Unmarshal(source, &document); err != nil {
				return err
			}
			entries, ok := document["rules"].([]any)
			if !ok {
				return fmt.Errorf("rule file %s has no rules list", current.SourceFile)
			}
			var selected any
			for _, entry := range entries {
				mapping, ok := entry.(map[string]any)
				if ok && mapping["id"] == current.ID {
					selected = mapping
					break
				}
			}
			if selected == nil {
				return fmt.Errorf("rule %s not found in %s", current.ID, current.SourceFile)
			}
			document["rules"] = []any{selected}
			data, err := yaml.Marshal(document)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(stdout, "%s\n---\n%s", current.ID, data); err != nil {
				return err
			}
			targetProject := project
			if targetProject == "" {
				targetProject = "example-prod"
				fmt.Fprintln(stdout, "rendered commands use placeholder project: example-prod")
			}
			values := map[string]any{"project": targetProject, "project_id": targetProject, "params": current.Params, "ctx": map[string]any{"project": targetProject, "project_id": targetProject}}
			fmt.Fprintln(stdout, "params:")
			paramNames := make([]string, 0, len(current.Params))
			for name := range current.Params {
				paramNames = append(paramNames, name)
			}
			sort.Strings(paramNames)
			for _, name := range paramNames {
				value := current.Params[name]
				fmt.Fprintf(stdout, "  %s: default=%v effective=%v\n", name, value, value)
			}
			fmt.Fprintf(stdout, "verification: %s\ncommands:\n", level)
			for _, step := range current.Collect {
				command, rendered := makeDryRunCommand(step, values)
				if command.Type == "" {
					continue
				}
				if rendered {
					if command.Method != "" {
						fmt.Fprintf(stdout, "  %s: %s %s\n", step.ID, command.Method, command.URL)
					} else {
						fmt.Fprintf(stdout, "  %s: %s %s\n", step.ID, command.Type, strings.Join(command.Argv, " "))
					}
				} else {
					fmt.Fprintf(stdout, "  %s: %s\n", step.ID, command.Template)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&project, "project", "", "Project ID used to render command templates")
	return cmd
}
