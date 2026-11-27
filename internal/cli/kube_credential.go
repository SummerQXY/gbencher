package cli

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/SummerQXY/gbencher/internal/auth"
	"github.com/SummerQXY/gbencher/internal/collect"
	"github.com/SummerQXY/gbencher/internal/engine"
	"github.com/spf13/cobra"
)

type kubeCredentialFlags struct {
	account, impersonate, quotaProject string
}

func kubeCredentialCmd(stdout, stderr io.Writer, env []string) *cobra.Command {
	flags := kubeCredentialFlags{}
	cmd := &cobra.Command{
		Use:    "__kube-credential",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := runKubeCredential(cmd.Context(), flags, stdout, env); err != nil {
				_, _ = fmt.Fprintln(stderr, "gbench: unable to obtain Kubernetes credentials")
				return &exitError{code: 3}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&flags.account, "account", "", "gcloud account")
	cmd.Flags().StringVar(&flags.impersonate, "impersonate-service-account", "", "Service account to impersonate")
	cmd.Flags().StringVar(&flags.quotaProject, "quota-project", "", "Quota project")
	return cmd
}

func runKubeCredential(ctx context.Context, flags kubeCredentialFlags, stdout io.Writer, env []string) error {
	if flags.account == "" {
		return fmt.Errorf("credential account is required")
	}
	baseEnv := env
	if baseEnv == nil {
		baseEnv = []string{}
	}
	gcloud, err := lookPath("gcloud", baseEnv)
	if err != nil {
		return fmt.Errorf("gcloud executable not found")
	}
	childEnv := collect.ChildEnv(baseEnv, engine.GcloudEnvOverrides())
	runner := credentialRunner{runner: collect.OSRunner{}}
	client, err := auth.Resolve(ctx, runner, gcloud, childEnv, nil, auth.Options{
		Account: flags.account, Impersonate: flags.impersonate, QuotaProject: flags.quotaProject,
	})
	if err != nil {
		return fmt.Errorf("credential identity could not be resolved")
	}
	token, err := client.Token(ctx)
	if err != nil {
		return fmt.Errorf("access token could not be obtained")
	}
	data, err := auth.ExecCredentialV1(token, time.Now().Add(50*time.Minute))
	if err != nil {
		return fmt.Errorf("credential response could not be encoded")
	}
	if _, err := stdout.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("credential response could not be written")
	}
	return nil
}

type credentialRunner struct{ runner collect.Runner }

func (r credentialRunner) Run(ctx context.Context, command collect.Exec, limits collect.Limits) (collect.Output, error) {
	if limits.Timeout <= 0 {
		limits.Timeout = 120 * time.Second
	}
	if limits.MaxOutput <= 0 {
		limits.MaxOutput = 64 << 20
	}
	return r.runner.Run(ctx, command, limits)
}
