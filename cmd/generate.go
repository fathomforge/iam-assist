package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/fathomforge/iam-assist/internal/policy"
	"github.com/fathomforge/iam-assist/internal/provider"
	"github.com/fathomforge/iam-assist/internal/terraform"
)

var generateCmd = &cobra.Command{
	Use:   "generate [request]",
	Short: "Convert a natural language access request into a GCP IAM policy",
	Long: `Generate converts plain English access requests into least-privilege
GCP IAM policies. Optionally refine with a second AI pass and output Terraform HCL.

Examples:
  iam-assist generate "Let the data team read BigQuery datasets in analytics-prod"
  iam-assist generate --refine "Deploy Cloud Run services in staging project"
  iam-assist generate --terraform --out main.tf "Storage viewer for etl-sa@myproject.iam.gserviceaccount.com"
  echo "read access to GCS bucket my-data" | iam-assist generate -`,
	Args: cobra.MaximumNArgs(1),
	RunE: runGenerate,
}

func init() {
	rootCmd.AddCommand(generateCmd)

	generateCmd.Flags().Bool("refine", false, "run a second-pass least-privilege refinement")
	generateCmd.Flags().Bool("terraform", false, "output Terraform HCL")
	generateCmd.Flags().Bool("json", false, "output raw JSON recommendation")
	generateCmd.Flags().StringP("out", "o", "", "write output to file instead of stdout")
	generateCmd.Flags().StringSlice("context", nil, "additional context hints (e.g., --context 'project: my-proj')")
	generateCmd.Flags().Float64("temperature", 0.1, "AI temperature (0.0-1.0)")
}

func runGenerate(cmd *cobra.Command, args []string) error {
	// 1. Resolve the request string.
	request, err := resolveRequest(args)
	if err != nil {
		return err
	}

	// 2. Initialize the AI provider.
	p, err := initProvider()
	if err != nil {
		return err
	}

	// 3. Build options.
	refine, _ := cmd.Flags().GetBool("refine")
	contextHints, _ := cmd.Flags().GetStringSlice("context")
	temperature, _ := cmd.Flags().GetFloat64("temperature")

	opts := policy.GenerateOptions{
		Refine:       refine,
		ContextHints: contextHints,
		Temperature:  temperature,
	}

	// 4. Generate.
	gen := policy.NewGenerator(p)

	fmt.Fprintf(os.Stderr, "🔍 Analyzing request with %s...\n", p.Name())
	// Refinement does two sequential AI calls and the second one produces
	// strictly larger output, so give the whole pipeline more headroom when
	// --refine is set.
	timeout := 60 * time.Second
	if refine {
		timeout = 240 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	rec, err := gen.Generate(ctx, request, opts)
	if err != nil {
		// Refinement failure is non-fatal: rec is the unrefined first-pass
		// result, which is still usable. Warn on stderr and continue.
		if errors.Is(err, policy.ErrRefinementFailed) && rec != nil {
			fmt.Fprintf(os.Stderr, "⚠ refinement skipped: %v\n", err)
			fmt.Fprintln(os.Stderr, "   (using unrefined first-pass result)")
		} else {
			return fmt.Errorf("generation failed: %w", err)
		}
	} else if refine {
		fmt.Fprintln(os.Stderr, "🔒 Refinement pass complete.")
	}

	// 5. Format output.
	outputJSON, _ := cmd.Flags().GetBool("json")
	outputTF, _ := cmd.Flags().GetBool("terraform")
	outFile, _ := cmd.Flags().GetString("out")

	var output string

	switch {
	case outputJSON:
		output, err = rec.ToJSON()
		if err != nil {
			return fmt.Errorf("JSON serialization failed: %w", err)
		}
	case outputTF:
		output, err = terraform.Render(rec)
		if err != nil {
			return fmt.Errorf("terraform rendering failed: %w", err)
		}
	default:
		// Terminal display + JSON for piping.
		if isTerminal() {
			output = policy.FormatTerminal(rec)
		} else {
			output, err = rec.ToJSON()
			if err != nil {
				return fmt.Errorf("JSON serialization failed: %w", err)
			}
		}
	}

	// 6. Write output.
	if outFile != "" {
		if err := os.WriteFile(outFile, []byte(output), 0644); err != nil {
			return fmt.Errorf("writing to %s: %w", outFile, err)
		}
		fmt.Fprintf(os.Stderr, "✅ Written to %s\n", outFile)
	} else {
		fmt.Print(output)
	}

	return nil
}

func resolveRequest(args []string) (string, error) {
	if len(args) == 1 {
		if args[0] == "-" {
			// Read from stdin.
			buf := make([]byte, 0, 4096)
			tmp := make([]byte, 256)
			for {
				n, err := os.Stdin.Read(tmp)
				buf = append(buf, tmp[:n]...)
				if err != nil {
					break
				}
			}
			request := strings.TrimSpace(string(buf))
			if request == "" {
				return "", fmt.Errorf("empty input from stdin")
			}
			return request, nil
		}
		return args[0], nil
	}
	return "", fmt.Errorf("please provide an access request as an argument or pipe via stdin with '-'")
}

// envVarForProvider returns the canonical environment variable name for a
// provider. Kept in one place so the friendly first-run message and any
// future onboarding command can't drift.
func envVarForProvider(name string) string {
	switch name {
	case "anthropic":
		return "ANTHROPIC_API_KEY"
	case "openai":
		return "OPENAI_API_KEY"
	case "google":
		return "GOOGLE_API_KEY"
	}
	return ""
}

func initProvider() (provider.Provider, error) {
	name := viper.GetString("provider")

	// Resolve API key: flag > provider-specific viper key > env var.
	apiKey := viper.GetString("api_key")
	if apiKey == "" {
		viperKey := strings.ToLower(envVarForProvider(name))
		if viperKey != "" {
			apiKey = viper.GetString(viperKey)
			if apiKey == "" {
				apiKey = os.Getenv(envVarForProvider(name))
			}
		}
	}

	model := viper.GetString("model")

	p, err := provider.New(name, apiKey, model)
	if err != nil {
		// The provider constructors return a consistent "API key required"
		// string when the key is missing. Intercept that single case and
		// replace the raw error with a friendly, copy-pasteable help block
		// on stderr so brand-new users aren't greeted with a Go error dump.
		if strings.Contains(err.Error(), "API key") && apiKey == "" {
			env := envVarForProvider(name)
			fmt.Fprintf(os.Stderr, "\n❌ No API key found for provider %q.\n\n", name)
			fmt.Fprintf(os.Stderr, "Set one of the following to get started:\n\n")
			if env != "" {
				fmt.Fprintf(os.Stderr, "  1. Environment variable (recommended):\n")
				fmt.Fprintf(os.Stderr, "       export %s=your-key\n\n", env)
			}
			fmt.Fprintf(os.Stderr, "  2. Command-line flag:\n")
			fmt.Fprintf(os.Stderr, "       iam-assist --api-key=your-key ...\n\n")
			fmt.Fprintf(os.Stderr, "  3. Config file ~/.iam-assist.yaml:\n")
			fmt.Fprintf(os.Stderr, "       provider: %s\n", name)
			if env != "" {
				fmt.Fprintf(os.Stderr, "       %s: your-key\n\n", strings.ToLower(env))
			}
			fmt.Fprintf(os.Stderr, "Switch providers anytime with --provider=anthropic|openai|google.\n")
			fmt.Fprintf(os.Stderr, "Need an API key? See https://fathomforge.dev/iam-assist/providers\n\n")
			return nil, fmt.Errorf("missing %s API key", name)
		}
		return nil, err
	}
	return p, nil
}

// isTerminal checks if stdout is a terminal.
func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
