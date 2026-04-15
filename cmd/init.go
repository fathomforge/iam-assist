package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Interactive first-run setup (writes ~/.iam-assist.yaml)",
	Long: `Init walks you through picking an AI provider, an optional default
project ID and internal domain, and writes a ready-to-use config to
~/.iam-assist.yaml so subsequent runs pick up your defaults automatically.

It does NOT prompt for your API key. Storing credentials in a config file
means they end up in backups and accidental commits; environment variables
are safer and are what iam-assist looks at first. Init prints the exact
export command you'll need at the end.

Examples:
  iam-assist init
  iam-assist init --config ./my-config.yaml`,
	RunE: runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	fmt.Println()
	fmt.Println("🛠  iam-assist setup")
	fmt.Println(strings.Repeat("─", 40))
	fmt.Println()

	reader := bufio.NewReader(os.Stdin)

	// 1. Provider choice
	provider, err := promptChoice(reader,
		"Which LLM provider do you want to use?",
		[]string{"google", "anthropic", "openai"},
		"google")
	if err != nil {
		return err
	}

	// 2. Optional default project
	fmt.Println()
	project, err := promptLine(reader,
		"Default GCP project ID (leave blank to skip):",
		"")
	if err != nil {
		return err
	}

	// 3. Optional internal domain — unlocks external-member detection in risk assessor
	fmt.Println()
	fmt.Println("Your organization's email domain is used to flag external members")
	fmt.Println("in generated policies (e.g. mycompany.com → alice@contractor.com is flagged).")
	domain, err := promptLine(reader,
		"Internal email domain (leave blank to skip):",
		"")
	if err != nil {
		return err
	}

	// 4. Resolve config path
	configPath, _ := cmd.Flags().GetString("config")
	if configPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("resolving home directory: %w", err)
		}
		configPath = filepath.Join(home, ".iam-assist.yaml")
	}

	// 5. If file exists, confirm overwrite
	if _, err := os.Stat(configPath); err == nil {
		fmt.Println()
		fmt.Printf("⚠  %s already exists.\n", configPath)
		confirm, _ := promptLine(reader, "Overwrite? [y/N]:", "n")
		if !strings.EqualFold(strings.TrimSpace(confirm), "y") {
			fmt.Println("Cancelled.")
			return nil
		}
	}

	// 6. Write the YAML
	var b strings.Builder
	b.WriteString("# iam-assist configuration — written by `iam-assist init`.\n")
	b.WriteString("# Do NOT store API keys here; use environment variables instead.\n\n")
	b.WriteString(fmt.Sprintf("provider: %s\n", provider))
	if project != "" || domain != "" {
		b.WriteString("\norg:\n")
		if project != "" {
			b.WriteString(fmt.Sprintf("  default_project: %s\n", project))
		}
		if domain != "" {
			b.WriteString(fmt.Sprintf("  domain: %s\n", domain))
		}
	}
	b.WriteString("\ndefaults:\n")
	b.WriteString("  refine: false\n")
	b.WriteString("  temperature: 0.1\n")

	if err := os.WriteFile(configPath, []byte(b.String()), 0644); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}

	// 7. Print next steps
	fmt.Println()
	fmt.Printf("✅ Wrote %s\n", configPath)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println()
	env := envVarForProvider(provider)
	fmt.Printf("  1. Set your API key in your shell rc (e.g. ~/.zshrc):\n")
	fmt.Printf("       export %s=your-key-here\n\n", env)
	fmt.Printf("  2. Open a new shell or `source` your rc, then test:\n")
	fmt.Printf("       iam-assist generate \"Read BigQuery datasets in my-project\"\n\n")
	fmt.Println("  3. Try `--refine` for a second-pass least-privilege review,")
	fmt.Println("     or `--terraform` to get ready-to-apply HCL:")
	fmt.Println("       iam-assist generate --refine --terraform -o policy.tf \"...\"")
	fmt.Println()
	return nil
}

// promptLine reads a single line of user input, trimming trailing whitespace.
// If the user presses Enter without typing, def is returned.
func promptLine(r *bufio.Reader, prompt, def string) (string, error) {
	if def != "" {
		fmt.Printf("%s [%s] ", prompt, def)
	} else {
		fmt.Printf("%s ", prompt)
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("reading input: %w", err)
	}
	line = strings.TrimRight(line, "\r\n ")
	if line == "" {
		return def, nil
	}
	return line, nil
}

// promptChoice asks the user to pick one of a set of options. Typing any
// prefix of an option counts (so "g" picks "google"). Enter picks the default.
func promptChoice(r *bufio.Reader, prompt string, options []string, def string) (string, error) {
	fmt.Printf("%s\n", prompt)
	for _, o := range options {
		marker := " "
		if o == def {
			marker = "*"
		}
		fmt.Printf("  %s %s\n", marker, o)
	}
	for {
		line, err := promptLine(r, "Choice:", def)
		if err != nil {
			return "", err
		}
		line = strings.ToLower(strings.TrimSpace(line))
		for _, o := range options {
			if line == o || strings.HasPrefix(o, line) {
				return o, nil
			}
		}
		fmt.Printf("Please pick one of: %s\n", strings.Join(options, ", "))
	}
}
